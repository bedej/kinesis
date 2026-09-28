import Foundation
import KinesisCore
import OSLog
import Security

/// Apple TV remote commands for Home Assistant's `remote.send_command` (apple_tv integration).
enum TVCommand: String, CaseIterable, Sendable {
    case up, down, left, right, select, menu, home
    case playPause = "play_pause"
    case volumeUp = "volume_up", volumeDown = "volume_down"
    case skipForward = "skip_forward", skipBackward = "skip_backward"

    var title: String {
        switch self {
        case .up: "up"
        case .down: "down"
        case .left: "left"
        case .right: "right"
        case .select: "click (select)"
        case .menu: "back (menu)"
        case .home: "home"
        case .playPause: "play / pause"
        case .volumeUp: "volume up"
        case .volumeDown: "volume down"
        case .skipForward: "skip forward"
        case .skipBackward: "skip back"
        }
    }

    /// Swipes steer the focus; index click selects; middle double tap goes back.
    static func command(for gesture: RecognizedGesture) -> TVCommand? {
        switch gesture {
        case .swipe(.up): .up
        case .swipe(.down): .down
        case .swipe(.left): .left
        case .swipe(.right): .right
        case .tap(.indexTap): .select
        case .tap(.middleDoubleTap): .menu
        case .tap(.indexDoubleTap): .playPause
        // A middle hold scrubs, so Home moves to the middle single tap.
        case .tap(.middleTap): .home
        case .tap(.middleHold): nil
        }
    }
}

/// Sends Apple TV remote commands through a Home Assistant server's REST API.
/// The long-lived access token lives in the keychain; the URL and entity live in defaults.
struct HomeAssistantRemote: Sendable {
    let baseURL: String
    let entityID: String
    let token: String

    private static let log = Logger(subsystem: "local.callbacked.kinesis", category: "homeassistant")

    private func endpoint(_ path: String) throws -> URL {
        let trimmed = baseURL.trimmingCharacters(in: .whitespacesAndNewlines).trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        guard let url = URL(string: trimmed + path), url.scheme?.hasPrefix("http") == true else {
            throw KinesisError(message: "Enter your Home Assistant address, like http://homeassistant.local:8123")
        }
        guard !token.isEmpty else { throw KinesisError(message: "Add a Home Assistant access token") }
        return url
    }

    /// Lists the server's `remote.` entities and says whether the configured one can take commands.
    /// Home Assistant answers 200 to a service call even for a missing or switched-off entity.
    func check() async throws -> String {
        var request = URLRequest(url: try endpoint("/api/states"), timeoutInterval: 6)
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        let (data, response) = try await URLSession.shared.data(for: request)
        let status = (response as? HTTPURLResponse)?.statusCode ?? 0
        guard status == 200 else {
            throw KinesisError(message: status == 401 ? "Home Assistant refused the access token" : "Home Assistant answered HTTP \(status)")
        }
        let states = (try JSONSerialization.jsonObject(with: data) as? [[String: Any]]) ?? []
        let remotes = states.compactMap { state -> (id: String, state: String, name: String)? in
            guard let id = state["entity_id"] as? String, id.hasPrefix("remote.") else { return nil }
            let name = (state["attributes"] as? [String: Any])?["friendly_name"] as? String ?? id
            return (id, state["state"] as? String ?? "?", name)
        }
        let list = remotes.map { "\($0.id) (\($0.name), \($0.state))" }.joined(separator: "; ")
        Self.log.notice("Remote entities: \(list, privacy: .public)")
        guard !remotes.isEmpty else { return "No remote entities found. Is the Apple TV integration set up?" }
        guard let mine = remotes.first(where: { $0.id == entityID }) else {
            return "\(entityID) doesn't exist. Remotes found: \(list)"
        }
        if mine.state != "on" { return "\(entityID) is \(mine.state). Turn it on in Home Assistant, or wake the Apple TV." }
        return "\(entityID) is on and ready (\(mine.name))."
    }

    /// The Apple TV integration names its media player after the remote.
    var mediaPlayerID: String { "media_player." + entityID.dropFirst("remote.".count) }

    struct Playback: Sendable {
        let state: String
        let app: String?
        /// Where playback is, projected to now while playing. Nil when the app doesn't report it.
        let position: Double?
        let duration: Double?
    }

    /// The Apple TV's playback state: `playing`, `paused`, `idle`, `standby`, …
    func playback() async throws -> Playback {
        var request = URLRequest(url: try endpoint("/api/states/" + mediaPlayerID), timeoutInterval: 3)
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        let (data, response) = try await URLSession.shared.data(for: request)
        guard (response as? HTTPURLResponse)?.statusCode == 200,
              let json = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw KinesisError(message: "Home Assistant couldn't find \(mediaPlayerID)")
        }
        let state = json["state"] as? String ?? "unknown"
        let attributes = json["attributes"] as? [String: Any] ?? [:]
        var position = (attributes["media_position"] as? NSNumber)?.doubleValue
        if state == "playing", let reported = position, let stamp = attributes["media_position_updated_at"] as? String,
           let updated = ISO8601DateFormatter.withFraction.date(from: stamp) ?? ISO8601DateFormatter().date(from: stamp) {
            position = reported + Date().timeIntervalSince(updated)
        }
        return Playback(state: state, app: attributes["app_name"] as? String, position: position,
                        duration: (attributes["media_duration"] as? NSNumber)?.doubleValue)
    }

    func seek(to seconds: Double) async throws {
        try await call("media_player", "media_seek", ["entity_id": mediaPlayerID, "seek_position": max(0, seconds)],
                       describing: "seek \(Int(seconds))s")
    }

    func send(_ command: TVCommand) async throws {
        guard entityID.hasPrefix("remote.") else { throw KinesisError(message: "Use the Apple TV's remote entity, like remote.living_room") }
        try await call("remote", "send_command", ["entity_id": entityID, "command": command.rawValue], describing: command.rawValue)
    }

    private func call(_ domain: String, _ service: String, _ data: [String: Any], describing label: String) async throws {
        var request = URLRequest(url: try endpoint("/api/services/\(domain)/\(service)"), timeoutInterval: 4)
        request.httpMethod = "POST"
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONSerialization.data(withJSONObject: data)
        let (_, response) = try await URLSession.shared.data(for: request)
        let status = (response as? HTTPURLResponse)?.statusCode ?? 0
        Self.log.notice("Sent \(label, privacy: .public) to \(entityID, privacy: .public): HTTP \(status, privacy: .public)")
        switch status {
        case 200..<300: return
        case 401, 403: throw KinesisError(message: "Home Assistant refused the access token")
        case 400, 404: throw KinesisError(message: "Home Assistant couldn't find \(entityID)")
        default: throw KinesisError(message: "Home Assistant answered HTTP \(status)")
        }
    }
}

extension ISO8601DateFormatter {
    /// Home Assistant timestamps carry fractional seconds.
    nonisolated(unsafe) static let withFraction: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter
    }()
}

/// One keychain item for the Home Assistant long-lived access token.
enum HomeAssistantToken {
    private static let service = "local.callbacked.kinesis.homeassistant"
    private static let account = "token"

    static func load() -> String {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: AnyObject?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess, let data = item as? Data else { return "" }
        return String(decoding: data, as: UTF8.self)
    }

    static func save(_ token: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        SecItemDelete(query as CFDictionary)
        guard !token.isEmpty else { return }
        var attributes = query
        attributes[kSecValueData as String] = Data(token.utf8)
        attributes[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlock
        SecItemAdd(attributes as CFDictionary, nil)
    }
}
