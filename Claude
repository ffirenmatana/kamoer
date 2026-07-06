# Local Home Assistant control of the Kamoer X2SR (no cloud, no app) — full teardown + how to replicate

**TL;DR:** The Kamoer X2SR auto water changer has no official Home Assistant
integration and no local API. I intercepted its network traffic, decoded the
protocol, and now drive it **entirely from my local Mosquitto + Home Assistant**
— start/stop the fill and drain heads with a chosen volume, and read the pump's
telemetry back — with the Kamoer cloud completely out of the loop. Here's exactly
how it works and how you can replicate it on your own unit.

⚠️ This is DIY reverse-engineering of your own hardware. It takes the pump off
Kamoer's cloud (the phone app will show it "offline"). It's reversible. Don't do
this on anything you can't afford to fiddle with, and be careful actuating a pump
that moves saltwater into your system.

---

## What the X2SR actually is, under the hood

- It's an **ESP8266** running **Alibaba Cloud IoT (Link Kit)**. It talks
  **MQTT wrapped in TLS on port 1883** to an Alibaba broker.
- Two findings made this whole thing possible:
  1. **It does not validate the server's TLS certificate.** It will happily
     complete a TLS handshake against a self-signed cert. That means you can
     stand in the middle of its "encrypted" connection.
  2. **Its entire control protocol is tunnelled through a single text property
     called `PumpSerialNumber`** — a hex string — inside otherwise-standard
     Alibaba MQTT messages.

### The MQTT topics (Alibaba thing-model)
- Commands go to:  `/sys/<ProductKey>/<DeviceName>/thing/service/property/set`
- The device posts telemetry to: `/sys/<ProductKey>/<DeviceName>/thing/event/property/post`
- Payload shape:
  `{"method":"thing.service.property.set","id":"<any>","params":{"PumpSerialNumber":"<HEX>"},"version":"1.0.0"}`

For the X2SR the **ProductKey is `a1UbfLPJj7A`** (this appears to be the same for
all X2SR units — it identifies the product). The **DeviceName** and the MQTT
**password** are unique to your unit; you capture them (below).

### The decoded control frame (the hex inside `PumpSerialNumber`)
```
[seq] 02 00 07 00 08 00 0e [CH] [ACT] 00 [volume: float32, big-endian]
  seq    = a message-counter byte. The device just echoes it — any value works.
  CH     = 01 -> Add Sea Water (fill head)   |  00 -> Discharge (drain head)
  ACT    = 01 -> START                        |  00 -> STOP
  volume = target volume in mL as an IEEE-754 float32.
           1000 mL = 447a0000,  500 mL = 43fa0000,  50 mL = 42480000
```
Example — **start the fill head for 1000 mL**: `A00200070008000e010100447a0000`

There's also a **read-only status poll** that makes the pump dump its telemetry
(running state + live float32 volume counters):  `[seq]00000000080005`

---

## The architecture

```
 X2SR (ESP8266)                 Your router / a small proxy                Your Mosquitto + Home Assistant
   │  MQTT-over-TLS :1883             │                                            │
   │                                  │  TLS-terminating "injecting proxy":        │
   └── redirected (DNS or DNAT) ─────►│   • presents a self-signed RSA cert        │
                                      │   • relays plaintext MQTT to your broker ──┼─► logs in as the device
                                      │   • **injects a SUBSCRIBE** for the        │
                                      │     command topic right after CONNECT      │
                                      │   • hides the resulting SUBACK             │
                                      └────────────────────────────────────────────┘
```

Two non-obvious things you MUST handle, or it won't work:

1. **The proxy needs an RSA self-signed cert, and TLS 1.2 with a legacy RSA
   cipher.** The ESP8266 offers old ciphers (e.g. `AES256-SHA256`). If your
   broker/proxy only presents a modern ECDSA cert (e.g. a Let's Encrypt cert) the
   handshake dies with "no shared cipher." (In Python's `ssl`, set
   `ctx.set_ciphers("ALL:@SECLEVEL=0")`.)

2. **The device never sends its own MQTT SUBSCRIBE.** Alibaba's platform uses
   *server-side* subscriptions, so a normal broker has nothing to route commands
   to — you can publish all day and the pump ignores it. The fix: the proxy
   **injects a `SUBSCRIBE /sys/<pk>/<dn>/thing/service/#` on the device's session
   right after it connects**, and swallows the SUBACK so the device's SDK isn't
   confused. After that, commands you publish are delivered to the pump.

---

## Step-by-step to replicate

You need: your reef LAN, an MQTT broker (the HA Mosquitto add-on is fine), and a
way to (a) run a small proxy and (b) redirect the pump's traffic to it.

**1. Find the pump on your network.** Look for an Espressif MAC. Confirm it holds
a connection to an Alibaba IP (the `47.236.x.x` range) on port 1883.

**2. Capture the plaintext protocol (one-time).** Point the pump's broker
connection at a self-signed TLS listener and log what flows. `socat` is perfect:
```
socat -x -v OPENSSL-LISTEN:8883,cert=fake.crt,key=fake.key,verify=0,reuseaddr,fork \
           OPENSSL:<real-alibaba-ip>:1883,verify=0
```
(Generate `fake.crt/fake.key` with `openssl req -x509 -newkey rsa:2048 ...`.)
Redirect the pump to this listener (see step 5), then open the Kamoer app and
press some buttons. In the capture you'll see, in the clear:
- the device's **CONNECT** → your **DeviceName**, MQTT **username**
  (`<DeviceName>&<ProductKey>`) and **password**;
- the **commands** as `PumpSerialNumber` hex — decode them with the frame above.

**3. Let the device log in to YOUR broker.** Add the device's captured
username/password as a Mosquitto login (HA Mosquitto add-on → `logins`). The
password is a fixed-timestamp HMAC, so it's stable.

**4. Run the injecting proxy.** A ~120-line Python asyncio script: TLS listen
(RSA cert), relay to your broker, inject the SUBSCRIBE after CONNACK, swallow the
SUBACK. (Full script in the repo — `kamoer_proxy.py`.)

**5. Redirect the pump to the proxy.** Two options:
   - **DNS override (most portable):** if the pump resolves its broker by
     hostname (Alibaba Link Kit typically uses
     `<ProductKey>.iot-as-mqtt.<region>.aliyuncs.com`), add a local DNS rewrite
     (Pi-hole / AdGuard / your router's DNS) pointing that name at the proxy host.
     No router shell needed.
   - **Router DNAT (what I used):** on the router, redirect the pump's outbound
     `:1883` to the proxy: `iptables -t nat -I PREROUTING -s <pump-ip> -p tcp
     --dport 1883 -j DNAT --to-destination <proxy-ip>:8883`. If the proxy is on a
     different host than the router, add a matching `MASQUERADE` (hairpin NAT).

**6. Control it from Home Assistant.** Publish the command frames with
`mqtt.publish`. Encode the volume float with the template `pack()` function:
`{{ pack(volume|float, '>f').hex() }}`. Subscribe to the `.../event/property/post`
topic for telemetry. (Full HA package in the repo — `kamoer.yaml`: an
`input_number` for volume, start/stop scripts for both heads, a status-poll
script, and a telemetry sensor.)

**7. Test safely.** First fire the **read-only status poll** — if the pump
answers with a telemetry blob, your command path works end-to-end. Then do a tiny
metered START (e.g. 50 mL) and an explicit STOP a few seconds later, watching the
pump. Only then trust bigger volumes.

---

## "Can this just be a Home Assistant integration?"

Mostly yes, with one caveat:
- The **proxy** can be shipped as a **Home Assistant add-on** (it's just a Python
  container). Point the redirect at the HA host and you don't need a separate box.
- The **control entities** are already a HA package and could be a HACS custom
  integration or blueprint.
- The **one irreducibly-external step is the redirect** (DNS rewrite or router
  DNAT), because HA can't change how your pump routes its own traffic. That's a
  one-time setup the user does on their router/DNS — everything else can be
  packaged.

---

## Caveats / gotchas
- **The phone app will show the pump offline** once you redirect it — it's off
  Kamoer's cloud. Fully reversible (drop the redirect and it goes back).
- **Make your proxy + redirect survive reboots** (systemd/init or a HA add-on),
  and re-assert router DNAT if your firewall software rebuilds its rules.
- **Auto-stop behaviour:** I confirmed explicit START/STOP works reliably; I did
  not exhaustively confirm whether the pump auto-stops at the target volume. Use
  explicit STOP (or a timeout guard) in any unattended automation, and keep test
  volumes tiny until you're sure.
- This is one person's teardown of one unit; firmware revisions may differ.
