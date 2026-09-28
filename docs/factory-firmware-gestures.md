# factory firmware: what got gestures working

debugging notes from 2026-09-26 on one band (`Meta Band 00CP` / `Meta Band-6B00CP`).
all times are Mac local time (PDT). band-log times are the band's own uptime clock,
which ran about 18:01:52 behind the Mac's clock that evening.

## the two firmwares seen

| | factory (after every factory reset) | Meta AI app update |
|---|---|---|
| firmware revision (GATT `2A26`) | `5c2b1ca1f73b+` | `79a235830f7f+` |
| software revision (`2A28`) | `1043538475` | `770435746` |
| input PSM | 129 (`81 00`) | 255 (`ff 00`) |
| RequestEncryption supported parameters | 27 | 3 |
| parameters the band insists on | 26 | 3 |
| EnableEncryption extra fields | `7=1`, `8=1` | none |
| gestures | working (after the steps below) | never arrived |

the author's tested band reported `297b870dc9be+`, PSM 255 and parameters 3.
a factory reset returns the band to `5c2b1ca1f73b+`; only the Meta AI app installs
`79a235830f7f+`. everything below is about the factory firmware.

## protocol fixes needed before anything streamed

each of these was required. none of them alone enabled gestures.

1. **PSM from the characteristic.** `BandConnection` read the PSM characteristic and
   required `ff 00`. it now parses a little-endian UInt16 and opens that PSM.
2. **AirShield parameters 26.** the band offers 27 and then confirms 26 whatever the
   host picks. verified recipe: the parameter-31 encryption key
   (`HKDF(S, salt=SHA256(C‖R), info="AirShield")`), the encryption key reused as the MAC
   key, and the `02 02 00 00` MAC prefix. the first live guess verified the band's packet
   MAC and decrypted its identity response. selected when the offer has bits 2, 8 and 16
   but not 4 (`chosen & 26 == 26 && chosen & 4 == 0`).
3. **full-block DataX padding.** this firmware pads an already aligned frame with a whole
   block of `d0` (0xc0 + 16). `DataXReceiver` only stripped 1–15, so the 16 leftover
   bytes parsed as a ~20 KB frame length and hid every later frame.
4. **session-tagged link channel.** link setup replies arrive on `0x9d01` / `0x9502`
   (session-tagged) instead of `0x8001` / `0x8003`. the link check now matches
   `channel & 0x80ff == 0x8001`.

with those in place, the ownership ceremony completed at 18:15:02 (stored identity for
`001CAD40-1E18-FD37-938D-DAB2637A7352`) and streaming started at 18:17:06.

## timeline after the claim

| time | run | streams requested | hand | result |
|---|---|---|---|---|
| 18:17:03 | connect (pid 19303) | 3, 6 (8=0) | right, then **left at 18:17:27** | ~128 gyro samples/s. no gesture frames. the user reached the app's gesture test page; gestures didn't register |
| 18:19:06 | connect (pid 19650), non-motion frames logged | 3, 6 | left | 90 s of user gestures: **zero** `0200020d` frames. only gyro and battery replies |
| 18:21:37 | connect (pid 20022) | 3, 6 + **4, 5, 7, 9–13, 16–20, 22, 23, 25–31** | left | many new stream types appeared (below). no gestures attempted |
| 18:22:38 | connect (pid 20230), band log decoded | same full set | left | **band loaded the gesture model** (see band log below). no gestures attempted |
| 18:23:20 | connect (pid 20277), 100 s recording | same full set | left | user gestured: **gestures arrived**. band woke the model at 18:23:33 on the first gesture |
| 18:26:21 | connect (pid 20435) | 3, 6 + 10 (Logging only) | left | 36 gesture frames in 10 s (real swipes: left/right/up) |
| 18:26:51 | connect (pid 20479) | 3, 6 + 4, 10 | left | 31 gesture frames in 10 s |
| 18:31:42 | normal launch (pid 20556) | 3, 6 (defaults) | left | handed back to the user; gestures reported working |

## candidate causes, most likely first

none of these is isolated yet. reproducing from a fresh factory reset is what would
settle it.

1. **one of the extra stream-control flags.** the band's gesture pipeline was `[Invalid]`
   until a connection enabled the full set. band log from the 18:22:38 run (band time
   00:20:48–00:20:49):

   ```text
   mconn: SC enable Gestures to chan …
   dsm: Transitioning: no_emg_streams -> operating, reason: emg_needed
   mconn: SC enable RawInference to chan …
   … (the full list below)
   config: config_rpc_request_handler : [seq id: 1]
   max_adc: COP: Got inference success at batch number: 30
   dsm: Transitioning: idle -> standby, reason: requested_model_changed
   emg_processing: Requesting switch to [Wake] pipeline
   emg_processing: Switching from [Invalid] pipeline to [None] pipeline
   emg_processing: Switching from [Wake] pipeline to [Wake] pipeline
   emg_processing: Model started at 1220435730 us
   emg_processing_ml_models: Init tensor working space from [0x20003420] size [174080]
   ```

   streams the band reported enabling, in its log order. unsupported ones say
   "not supported in this build":
   `RawCMSJ` (unsupported), `Gestures`, `RawInference`, `Acc`, `Gyro`, `Mag` (unsupported),
   `Quat` (disabled), `WakeStatus` (unsupported), `Logging`, `Telemetry` (unsupported),
   `BatteryUpdates`, `DeviceTelemetry`, `DeviceState`, `Uniband`, `RawEmgImuBatch`,
   `ConfigUpdate`, `AcloRaw` (unsupported), `RawCsa` (unsupported), `PipelineEvent`,
   `DcloRaw` (unsupported), `RawPreprocessing` (unsupported), `DetectorUpdate`,
   `KwaltzTelemetry`, `BandOrientationAlgoState`, `BandOrientationResult`.

   the subscription acknowledgement listed these flags as enabled:
   `3 4 5 6 10 12 13 16 17 19 22 23 27 28 29 30` (8 = 0). the flags it left out, 7, 9,
   11, 18, 20, 25, 26 and 31, match the eight unsupported names one for one.
   the field-number-to-name mapping is not otherwise confirmed. `Gestures` = 3,
   `Gyro` = 6 and `Quat` = 8 agree with the original notes; `RawInference` is probably 4
   and `Logging` 10.

   the strongest suspects are `RawInference`, `ConfigUpdate`, `DetectorUpdate`,
   `PipelineEvent` and `DeviceState`. the run at 18:21:37 had the same set and its band
   log wasn't decoded, so it's unknown whether the model loaded then and was torn down
   again at disconnect.

2. **the handedness write.** the hand went from right to left at 18:17:27. the model
   wake telemetry later reports `is_left_hand = 1`, and the model load says
   `requested_model_changed`. a hand change may request a new model that only loads
   once the EMG pipeline next runs. the full-stream connection could have been the
   first chance for that.

3. **the first gesture waking the model.** after the model loaded, it idled in
   `standby` until the first gesture at 18:23:33:

   ```text
   emg_processing: model switch complete
   emg_processing: Active seq[0] FIRST INFERENCE DONE
   model_dsm: Sent wake telemetry | reason = 5 | is_left_hand = 1
   model_dsm: emg_model_id = cc_od_resetlstm_F1017719999_260108
   ```

   the 18:17 and 18:19 sessions also had gestures, so a wake alone wasn't enough while
   the pipeline was `[Invalid]`.

4. **band worn and fitted.** each connection logs
   `dsm: operating_delay -> operating, reason: gates_met` and `emg_tightness_sbf_enable`.
   the band was on the wrist for the 18:19 session too, so this is unlikely to be the
   deciding factor.

5. **time or repeated connections after the claim.** the model loaded about 5 minutes
   and 5 connections after the claim. that could be coincidence. it can't be ruled out
   yet.

things that did **not** enable gestures on their own: the stream-state re-query (it
only
matters for the updated firmware's partial acknowledgement), the Logging stream, and raw
EMG. `RawCMSJ` isn't supported on this build, and the EMG configuration read fails.

## new stream types seen with the full set

| type | rate | notes |
|---|---|---|
| `0200020d` | per gesture | gestures, same schema as before (finger 3, action 4, derived 5) |
| `0200020f` | ~128/s | gyro (6-byte vector) |
| `02000210` | ~128/s | 6-byte vector, probably accelerometer |
| `02000229` | ~128/s | 256-byte sample blocks, probably `RawEmgImuBatch` |
| `0200020c` | ~64/s | three floats, probably `RawInference` or orientation |
| `02000316` | bursts | **band firmware log text**, printable UTF-8 inside the protobuf |

## how to reproduce the isolation test

1. factory reset the band (it returns to `5c2b1ca1f73b+`), forget it in macOS Bluetooth,
   and put it in pairing mode.
2. dev build (`./scripts/build.sh --dev`), then launch with
   `open --env KINESIS_AUTOCONNECT=1 dist/Kinesis.app`. it pairs an unclaimed band and
   connects a claimed one.
3. add `--env KINESIS_STREAMS=10` to get the band log (`Band log:` lines) with nothing
   else extra. then try one suspect at a time, for example `KINESIS_STREAMS=4,10`, and
   watch for `Switching from [Invalid] pipeline` and `requested_model_changed`.
4. keep the hand on its default the first time, to separate cause 2 from cause 1.
5. read logs with
   `log show --last 5m --info --style compact --predicate 'subsystem == "local.callbacked.kinesis"'`.

`KINESIS_P26="enc,mac,prefix"` overrides the parameter-26 recipe for experiments.
