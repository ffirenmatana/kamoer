# Kamoer X2SR — fully-local control (no cloud, no app)

Reverse-engineering notes and a working reference implementation for running a
**Kamoer X2SR** automatic water changer **entirely on your own LAN** — local
MQTT / Home Assistant only, with the Kamoer/Alibaba cloud and the phone app
completely out of the loop. You get start/stop of both heads with a chosen
volume, live telemetry, and safe automation.

> ⚠️ **Interoperability / DIY on hardware you own.** This takes the pump off the
> vendor cloud (the app will show it "offline") and is fully reversible. Nothing
> here targets anyone else's infrastructure — the proxy only ever sits between
> *your* pump and *your* broker. Actuating a pump moves water into/out of your
> system; test with tiny volumes first. No warranty; use at your own risk.

## What was learned

- The X2SR is an **ESP8266** running the **Alibaba Cloud IoT Link Kit**, speaking
  **MQTT over TLS on port 1883**.
- It **doesn't validate the server certificate** and uses a legacy TLS 1.2 RSA
  cipher, so transparent interception with a self-signed cert is trivial.
- Its login is **static** (fixed-timestamp HMAC) → replayable to your own broker.
- **All control + telemetry tunnel through one string property, `PumpSerialNumber`**
  (a hex frame).
- At cold boot the device **blocks until a few "cloud" requests are answered**
  (a LAN-prefix fetch, NTP-over-MQTT, a couple of acks) — every reply is a static
  per-device constant or a synthesised timestamp, so a tiny **local emulator fully
  replaces the cloud**.
- The device relies on **server-side subscriptions** and never subscribes to its
  own command topic, so the proxy must **inject a SUBSCRIBE** for it.
- The pump **auto-stops at the commanded volume** — a metered start is
  self-terminating (measured ~880–900 mL/min per head).

Full protocol, the cold-boot handshake, the telemetry decode, and a step-by-step
replication guide are in **[X2SR-REVERSE-ENGINEERING.md](X2SR-REVERSE-ENGINEERING.md)**.

## Repository contents

| File | What it is |
|---|---|
| [`X2SR-REVERSE-ENGINEERING.md`](X2SR-REVERSE-ENGINEERING.md) | The detailed technical writeup + replication guide |
| [`capture_proxy.py`](capture_proxy.py) | Transparent TLS MITM used to capture the protocol (also a cloud-relay fallback) |
| [`kamoer_local.example.py`](kamoer_local.example.py) | Pure-local proxy + boot-handshake emulator (the end state) |
| [`decode_mqtt.py`](decode_mqtt.py) | Decoder for a raw MQTT capture |
| [`kamoer.example.yaml`](kamoer.example.yaml) | Home Assistant package: control scripts, decoded telemetry sensors, safety automations |
| [`run.example.sh`](run.example.sh) | Supervisor: keeps the proxy alive + re-asserts the DNAT |
| [`99-kamoer.sh`](99-kamoer.sh), [`udm-boot.service`](udm-boot.service) | Boot hooks (example: UniFi/UDM) |

All `*.example.*` files use `<PLACEHOLDERS>` for every per-device value
(ProductKey, DeviceName, deviceSecret, LAN prefix, MQTT password, IPs). **You
capture your own** — see the writeup, §2 and §4. No device-specific secrets are
included in this repo.

## Quick start

1. Read [`X2SR-REVERSE-ENGINEERING.md`](X2SR-REVERSE-ENGINEERING.md).
2. Stand up the TLS terminator and DNAT the pump to it (§4).
3. Run `capture_proxy.py`, power-cycle the pump, and capture your device's
   handshake + credentials (§4, §6).
4. Add the device login to your broker; fill your captured values into the
   `*.example.*` files.
5. Switch to `kamoer_local.py`, power-cycle, confirm telemetry, then meter a
   small test change.

## Status

Pure-local control is validated end-to-end: cold boot on the local emulator,
command delivery, live telemetry into Home Assistant, and a supervised metered
water change that the device auto-stopped at target. Tested on one unit,
firmware `X2SR_GD_EN-1.1.15`; other revisions may differ.

## License

No license is currently specified, which means default "all rights reserved."
If you want others to freely reuse this, add a permissive license (e.g. MIT).
