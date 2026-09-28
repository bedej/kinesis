import CommonCrypto
import CryptoKit
import Foundation

public struct BandProtocolError: LocalizedError {
    public let message: String
    public init(_ message: String) { self.message = message }
    public var errorDescription: String? { message }
}

struct AirShieldKeys {
    let encryption: SymmetricKey
    let mac: SymmetricKey

    // Parameter 3 was verified on the original band firmware. Parameter 31 follows
    // neural-band-poc's airshield.py, verified there against the glasses link.
    init(secret: Data, challenge: Data, seed: Data, parameters: Int = 3) throws {
        guard secret.count == 32, challenge.count == 16, seed.count == 32 else {
            throw BandProtocolError("Invalid AirShield key material")
        }
        if parameters == 31 {
            let key = SymmetricKey(data: secret)
            encryption = HKDF<SHA256>.deriveKey(inputKeyMaterial: key, salt: Data(SHA256.hash(data: challenge + seed)),
                                                info: Data("AirShield".utf8), outputByteCount: 32)
            mac = HKDF<SHA256>.deriveKey(inputKeyMaterial: key,
                                         salt: Data(SHA256.hash(data: seed + challenge + Data("hmac_derive".utf8))),
                                         info: Data("AirShield".utf8), outputByteCount: 32)
            return
        }
        guard parameters == 3 else { throw BandProtocolError("Unsupported AirShield parameters \(parameters)") }
        let hashed = Data(SHA256.hash(data: secret))
        encryption = HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: hashed),
            salt: Data(SHA256.hash(data: hashed + challenge + seed)), info: Data("AirShield".utf8), outputByteCount: 32)
        mac = encryption
    }

    init(encryption: Data, mac: Data) {
        self.encryption = SymmetricKey(data: encryption)
        self.mac = SymmetricKey(data: mac)
    }
}

private func crypt(_ data: Data, key: SymmetricKey, iv: Data, operation: CCOperation) throws -> Data {
    guard key.bitCount == 256, iv.count == 16, !data.isEmpty, data.count % 16 == 0 else {
        throw BandProtocolError("Invalid AES block shape")
    }
    var output = Data(count: data.count + 16)
    var count = 0
    let capacity = output.count
    let status = key.withUnsafeBytes { keyBytes in
        iv.withUnsafeBytes { ivBytes in
            data.withUnsafeBytes { bytes in
                output.withUnsafeMutableBytes { destination in
                    CCCrypt(operation, CCAlgorithm(kCCAlgorithmAES), 0, keyBytes.baseAddress, 32,
                            ivBytes.baseAddress, bytes.baseAddress, data.count,
                            destination.baseAddress, capacity, &count)
                }
            }
        }
    }
    guard status == kCCSuccess else { throw BandProtocolError("AES operation failed: \(status)") }
    return output.prefix(count)
}

struct AirShieldCipher {
    let keys: AirShieldKeys
    private(set) var iv: Data
    private(set) var counter: UInt32
    /// Parameter 31 prefixes each packet MAC input with 02 02 00 00.
    var macPrefix = Data()

    mutating func encrypt(_ frame: Data) throws -> Data {
        let count = (16 - frame.count % 16) % 16
        let padded = frame + Data(repeating: UInt8(0xc0 + count), count: count)
        guard !padded.isEmpty, padded.count <= 4096 else { throw BandProtocolError("AirShield frame too large") }
        let ciphertext = try crypt(padded, key: keys.encryption, iv: iv, operation: CCOperation(kCCEncrypt))
        let body = Data([UInt8(ciphertext.count / 16 - 1)]) + ciphertext
        let tag = HMAC<SHA256>.authenticationCode(for: macPrefix + counter.littleEndianData + body, using: keys.mac)
        iv = Data(ciphertext.suffix(16))
        counter &+= 1
        return Data([0x40]) + Data(tag.prefix(8)) + body
    }

    mutating func decrypt(_ packet: Data) throws -> Data {
        let expected = HMAC<SHA256>.authenticationCode(for: macPrefix + counter.littleEndianData + packet.dropFirst(9), using: keys.mac)
        // Compare every byte before decrypting. No unauthenticated plaintext leaves this type.
        let difference = zip(expected.prefix(8), packet.dropFirst().prefix(8)).reduce(UInt8(0)) { $0 | ($1.0 ^ $1.1) }
        guard difference == 0 else { throw BandProtocolError("Band packet authentication failed") }
        let ciphertext = Data(packet.dropFirst(10))
        let plaintext = try crypt(ciphertext, key: keys.encryption, iv: iv, operation: CCOperation(kCCDecrypt))
        iv = Data(ciphertext.suffix(16))
        counter &+= 1
        return plaintext
    }
}

struct AirShieldReceiver {
    var cipher: AirShieldCipher
    private var pending = Data()

    init(cipher: AirShieldCipher) { self.cipher = cipher }

    mutating func feed(_ bytes: Data) throws -> [Data] {
        pending.append(bytes)
        var plaintext: [Data] = []
        while let marker = pending.first {
            if [0x81, 0x82].contains(marker), pending.count >= 2, pending[1] <= 1 {
                pending = Data(pending.dropFirst(2))
                continue
            }
            if [0x01, 0x02].contains(marker) {
                guard pending.count >= 2 else { break }
                let size = 3 + Int(pending[1])
                guard pending.count >= size else { break }
                pending = Data(pending.dropFirst(size))
                continue
            }
            if [0x81, 0x82].contains(marker), pending.count < 2 { break }
            guard [0x40, 0x41, 0x42].contains(marker) else {
                throw BandProtocolError("Unsupported band transport marker")
            }
            guard pending.count >= 10 else { break }
            let size = 10 + (Int(pending[9]) + 1) * 16
            guard pending.count >= size else { break }
            if marker == 0x40 { plaintext.append(try cipher.decrypt(Data(pending.prefix(size)))) }
            // Relay channels are not part of the authenticated input service.
            pending = Data(pending.dropFirst(size))
        }
        return plaintext
    }

    func finish() throws {
        guard pending.isEmpty else { throw BandProtocolError("Truncated AirShield packet") }
    }
}

extension FixedWidthInteger {
    var littleEndianData: Data { withUnsafeBytes(of: littleEndian) { Data($0) } }
    var bigEndianData: Data { withUnsafeBytes(of: bigEndian) { Data($0) } }
}

/// Diagnostic for undocumented AirShield parameters (e.g. 26 on newer band
/// firmware): tries known derivation ingredients against one received packet's
/// MAC and reports the combinations that verify. Never used for live traffic.
enum AirShieldProbe {
    static func test(packet: Data, secret: Data, hostChallenge: Data, hostSeed: Data,
                     bandChallenge: Data, bandSeed: Data, iv: Data, counter: UInt32) -> [String] {
        let packet = Data(packet)
        let hashed = Data(SHA256.hash(data: secret))
        let hmacLabel = Data("hmac_derive".utf8)
        func kdf(_ ikm: Data, _ saltInput: Data) -> SymmetricKey {
            HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: ikm), salt: Data(SHA256.hash(data: saltInput)),
                                   info: Data("AirShield".utf8), outputByteCount: 32)
        }
        var encryption: [(String, SymmetricKey)] = []
        var macs: [(String, SymmetricKey)] = [("secret", SymmetricKey(data: secret)), ("sha(secret)", SymmetricKey(data: hashed))]
        for (roles, c, r) in [("C=host,R=band", hostChallenge, bandSeed), ("C=band,R=host", bandChallenge, hostSeed)] {
            let hashedEnc = kdf(hashed, hashed + c + r), rawEnc = kdf(secret, c + r)
            encryption += [("p3 enc \(roles)", hashedEnc), ("p31 enc \(roles)", rawEnc)]
            macs += [("p3 enc \(roles)", hashedEnc), ("p31 enc \(roles)", rawEnc),
                     ("p31 mac \(roles)", kdf(secret, r + c + hmacLabel)), ("p7 mac \(roles)", kdf(hashed, r + c + hmacLabel + hashed))]
        }
        let prefixes: [(String, Data)] = [("none", Data()), ("02020000", Data([2, 2, 0, 0])), ("01010000", Data([1, 1, 0, 0])),
                                          ("02000000", Data([2, 0, 0, 0])), ("00000000", Data([0, 0, 0, 0]))]
        let counters: [(String, Data)] = [("LE", counter.littleEndianData), ("BE", counter.bigEndianData), ("none", Data())]
        let tag = packet.dropFirst().prefix(8), body = packet.dropFirst(9)
        var results: [String] = []
        for (macName, macKey) in macs {
            for (prefixName, prefix) in prefixes {
                for (counterName, counterBytes) in counters {
                    let code = HMAC<SHA256>.authenticationCode(for: prefix + counterBytes + body, using: macKey)
                    guard Data(code.prefix(8)) == Data(tag) else { continue }
                    var line = "MAC OK: key \(macName), prefix \(prefixName), counter \(counterName)"
                    let ciphertext = Data(packet.dropFirst(10))
                    for (encName, encKey) in encryption {
                        if let plain = try? crypt(ciphertext, key: encKey, iv: iv, operation: CCOperation(kCCDecrypt)) {
                            line += " | \(encName): \(plain.prefix(16).map { String(format: "%02x", $0) }.joined())…\(plain.suffix(2).map { String(format: "%02x", $0) }.joined())"
                        }
                    }
                    results.append(line)
                }
            }
        }
        return results
    }
}

extension AirShieldKeys {
    /// Experimental recipe for undocumented parameters (26). enc: "hashed" (p3/p7 branch)
    /// or "raw" (p31 branch); mac: "enc" (reuse), "p31", or "p7".
    init(experimental secret: Data, challenge: Data, seed: Data, enc: String, mac: String) {
        let hashed = Data(SHA256.hash(data: secret))
        func kdf(_ ikm: Data, _ saltInput: Data) -> SymmetricKey {
            HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: ikm), salt: Data(SHA256.hash(data: saltInput)),
                                   info: Data("AirShield".utf8), outputByteCount: 32)
        }
        let label = Data("hmac_derive".utf8)
        encryption = enc == "raw" ? kdf(secret, challenge + seed) : kdf(hashed, hashed + challenge + seed)
        switch mac {
        case "p31": self.mac = kdf(secret, seed + challenge + label)
        case "p7": self.mac = kdf(hashed, seed + challenge + label + hashed)
        default: self.mac = encryption
        }
    }
}
