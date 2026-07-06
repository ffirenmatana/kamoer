# Kamoer X2SR — Reverse-Engineering & Fully-Local Control

A detailed, reproducible writeup of how to take a **Kamoer X2SR** automatic water
changer (a Wi-Fi peristaltic pump that normally phones home to the Alibaba Cloud
IoT platform) and run it **entirely on your own LAN** — no vendor cloud, no
internet, no phone app — while exposing full start/stop/telemetry to your own
MQTT broker / Home Assistant.

Everything here was derived from a device I own, on my own network. Nothing below
is a vendor secret: it's the on-the-wire behaviour of a stock device, plus the
generic Alibaba "Link Kit" protocol. All values that are unique to a specific
unit (product key, device name, device secret, credentials, IPs, MAC) are shown
as `<PLACEHOLDERS>` — **you capture your own** using the method in §4.

> ⚠️ **Scope / ethics.** This is interoperability work on hardware you own so it
> keeps working without a cloud dependency. It is not an attack on Alibaba's
> infrastructure — the proxy only ever sits between *your* device and *your*
> broker. Don't point any of this at infrastructure you don't control.

---

## 1. TL;DR

- The X2SR is an **ESP8266** running the **Alibaba Cloud IoT Link Kit** SDK. It
  speaks **MQTT over TLS on port 1883** (note: TLS on 1883, not the usual 8883).
- It **does not validate the server's TLS certificate** and negotiates a legacy
  **TLS 1.2 RSA** cipher (`AES256-SHA256`). That makes transparent TLS
  interception with a self-signed cert trivial.
- Its MQTT login is **static** (fixed-timestamp HMAC), so it can be replayed to
  your own broker.
- **All control and telemetry are tunnelled through a single thing-model string
  property, `PumpSerialNumber`**, whose value is a hex-encoded binary frame.
- At cold boot the device **blocks until a handful of cloud requests are
  answered** (a LAN-prefix fetch, an NTP-over-MQTT exchange, a deviceinfo ack).
  Every one of those replies is either a **static per-device constant** or a
  **trivially synthesised timestamp** — so a tiny local "cloud emulator" fully
  replaces the cloud.
- The device relies on **server-side subscriptions**: it never subscribes to its
  own command topic, so a plain broker won't deliver commands to it. You fix this
  by **injecting a SUBSCRIBE** on the device's session.
- The pump **auto-stops at the commanded volume** — a metered start is
  self-terminating.

Two working architectures are described: a **transparent cloud-relay** (used to
capture the protocol, and a good fallback) and the end goal, a **pure-local
proxy + boot-handshake emulator**.

---

## 2. Placeholders (capture your own — §4)

| Placeholder | What it is | Where you get it |
|---|---|---|
| `<PK>` | Alibaba **ProductKey** (same for all X2SRs of a model) | MQTT topics / CONNECT |
| `<DN>` | Alibaba **DeviceName** (unique per unit) | MQTT topics / CONNECT |
| `<DEVICE_SECRET>` | Per-device secret returned by the LAN-prefix reply | boot capture |
| `<LAN_PREFIX>` | Per-device LAN comms prefix returned alongside it | boot capture |
| `<MQTT_USER>` | `"<DN>&<PK>"` | CONNECT |
| `<MQTT_PASS>` | Static HMAC password | CONNECT |
| `<DEVICE_IP>` | The pump's LAN IP | your DHCP table |
| `<DEVICE_MAC>` | The pump's MAC | your DHCP table |
| `<ROUTER_IP>` | Router/box that will host the proxy + DNAT | your network |
| `<BROKER_IP>` | Your MQTT broker (e.g. Home Assistant / Mosquitto) | your network |
| `<REGION>` | Alibaba region in the endpoint SNI, e.g. `ap-southeast-1` | TLS SNI at capture |

---

## 3. Device & stack identification

From the MQTT `CONNECT` packet and the boot log posts:

- SoC: **ESP8266**.
- SDK: **Alibaba Cloud IoT Link Kit** ("ilop"), `SDK 2.3.0_FY_1.6.0-1`, language C.
- Firmware string (example): `X2SR_GD_EN-1.1.15`.
- Transport: **MQTT over TLS, TCP/1883**, to `<REGION>` Alibaba IoT endpoint.
  Observed TLS SNI: `public.iot-as-mqtt.<REGION>.aliyuncs.com`; the broker is a
  round-robin IP pool (observed `47.236.x.x`).
- TLS: device offers/accepts **`AES256-SHA256` (TLS 1.2, RSA)** and **does not
  verify the server certificate**.

> Aside: not all Kamoer gear is on Alibaba/TLS. Some models (e.g. certain dosing
> pumps) speak **plaintext MQTT to AWS** on 1883 — easier still, no TLS to strip.
> Sniff yours first.

### MQTT credentials are static

The client identifier embeds Alibaba's "secure mode" auth params with a **fixed
timestamp**, which means the HMAC password never changes:

```
clientId : <DN>|securemode=2,timestamp=<FIXED>,signmethod=hmacsha1,...|
username : <DN>&<PK>
password : <MQTT_PASS>            # constant — replayable to your own broker
```

Add that exact `username`/`password` as a valid login on your broker (see §9).

---

## 4. Transport interception (TLS MITM)

Because the device ignores cert validation, you terminate its TLS with a
self-signed RSA cert and do whatever you like with the plaintext MQTT inside.

**4.1 Redirect the device to your proxy (router DNAT).** On a Linux-based router
(or any box the device's traffic passes through), redirect the device's MQTT to
your proxy port:

```sh
iptables -t nat -I PREROUTING 1 \
  -s <DEVICE_IP> -p tcp --dport 1883 \
  -j DNAT --to-destination <ROUTER_IP>:8883
```

(We listen on 8883 to avoid clashing with anything on 1883. Re-assert this rule
periodically if your router rebuilds its firewall.)

**4.2 Recover the real cloud IP (only needed for the cloud-relay mode).** Because
DNAT rewrites the destination, use `SO_ORIGINAL_DST` on the *accepted* socket to
learn the IP the device originally dialled:

```python
import socket, struct
SO_ORIGINAL_DST = 80   # <linux/netfilter_ipv4.h>
def original_dst(sock):
    raw = sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
    port = struct.unpack("!H", raw[2:4])[0]
    ip   = socket.inet_ntoa(raw[4:8])
    return ip, port
```

**4.3 Terminate the device TLS.** Self-signed RSA cert (the CN is irrelevant, the
device doesn't check it); allow the legacy cipher:

```sh
openssl req -x509 -newkey rsa:2048 -keyout fake.key -out fake.crt \
  -days 3650 -nodes -subj "/CN=iot.example.com"
```

```python
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain("fake.crt", "fake.key")
ctx.minimum_version = ssl.TLSVersion.TLSv1
ctx.set_ciphers("ALL:@SECLEVEL=0")     # permit the ESP8266's legacy RSA suite
```

**4.4 Capture the SNI** (useful for the cloud-relay upstream and to learn your
`<REGION>`):

```python
sni = {"name": None}
ctx.sni_callback = lambda s, name, c: sni.__setitem__("name", name)
```

That's the whole MITM. Everything after this is plaintext MQTT.

---

## 5. Application protocol (Alibaba Link Kit thing-model)

The device uses standard Alibaba "thing" topics, but instead of a rich thing
model it **tunnels a binary protocol through one string property** called
`PumpSerialNumber`.

**Topics** (all under `/sys/<PK>/<DN>/`):

| Direction | Topic | Purpose |
|---|---|---|
| you → device | `.../thing/service/property/set` | send a command frame |
| device → you | `.../thing/event/property/post` | telemetry / poll replies |
| device → you | `.../thing/service/property/set_reply` | command ACK (`code:200`) |

**Command payload** (publish to `.../property/set`):

```json
{"method":"thing.service.property.set","id":"<n>",
 "params":{"PumpSerialNumber":"<HEX>"},"version":"1.0.0"}
```

### 5.1 Control frame (the hex inside `PumpSerialNumber`)

```
[seq] 02 00 07 00 08 00 0e [CH] [ACT] 00 [volume float32 big-endian]
```

| Field | Bytes | Meaning |
|---|---|---|
| `seq` | 1 | command counter; **must change each command** (device dedups repeats). Use a monotonic byte 0–255. |
| fixed | `02 00 07 00 08 00 0e` | opcode/header (constant) |
| `CH` | 1 | pump head / channel: `01` and `00` are the two heads (which is "fill" vs "drain" depends on your plumbing) |
| `ACT` | 1 | `01` = START, `00` = STOP |
| `00` | 1 | constant |
| `volume` | 4 | IEEE-754 **float32, big-endian**, millilitres |

Volume examples: `447a0000` = 1000.0, `42c80000` = 100.0, `458ca000` = 4500.0.

Example — start head `01` for 4500 mL, seq `05`:
`050200070008000e010100458ca000`

### 5.2 Status poll (read-only)

```
[seq] 00 00 00 00 08 00 05
```

The device answers with a telemetry post (below). Don't poll *during* the
few seconds you're spacing out head-start commands (§11) — it can cause the
device to drop a start.

### 5.3 Telemetry decode

Telemetry arrives as `PumpSerialNumber` hex on `.../event/property/post`. There
are **two shapes**:

**Idle / config post** — key-value records, no live counters. Recognisable by the
run-flag byte being `00`. Example:

```
02 000026 00580005 00000000 03 000000 458cA000 ... 01 ... 42C80000 ... 02 ... 00989680 ...
                                     └ 4500.0 (a config value, NOT live volume)
```

**Running post** (reply while a change is active) — carries **both heads**. Using
character offsets into the hex string:

| Field | Hex chars | Notes |
|---|---|---|
| run flag | `[50:52]` | `00` = idle, `01` = running |
| head A target | `[32:40]` | float32 BE, the commanded volume |
| head A remaining | `[40:48]` | float32 BE, counts **down** to 0 |
| head B target | `[54:62]` | float32 BE |
| head B remaining | `[62:70]` | float32 BE |

`transferred = target − remaining`. Worked example (running):

```
05 000026 00580005 00000000 03 000100 458cA000 45899cA8 01 0100 458cA000 45877a00 02 ...
                                       │        │                │        └ B rem 4335.25 → xfer 164.75
                                       │        └ A rem 4403.33 → xfer 96.67
                                       └ target 4500.0 (both heads)
```

(Offsets are stable for a given firmware; verify against your own capture by
diffing an idle vs a running post.)

---

## 6. The cold-boot handshake (the key to going cloud-free)

The reason a naïve "just point it at a local broker" fails: on a cold boot the
device publishes a series of requests and **will not proceed to normal operation
(no telemetry, no actuation) until the "cloud" answers a few of them.** Capture
them once via the cloud-relay (§8), then replay/synthesise them locally.

The full boot sequence (payloads abbreviated), and what each needs:

1. `CONNECT` → broker `CONNACK` (your broker handles this once the login is valid).
2. Device `SUBSCRIBE /sys/<PK>/<DN>/thing/event/+/post_reply` → broker `SUBACK`.
3. Device `PUBLISH .../thing/deviceinfo/update` (device attributes)
   → **reply** `.../thing/deviceinfo/update_reply`:
   `{"code":200,"data":{},"id":<echo>,"message":"success","method":"thing.deviceinfo.update","version":"1.0"}`
4. Device `PUBLISH /ota/device/inform/<PK>/<DN>` (firmware version) → just a `PUBACK`.
5. Device `PUBLISH .../thing/lan/prefix/get`
   → **reply** `.../thing/lan/prefix/get_reply` — **static per device**:
   ```json
   {"code":200,"data":{"deviceSecret":"<DEVICE_SECRET>","prefix":"<LAN_PREFIX>",
    "productKey":"<PK>","deviceName":"<DN>"},
    "id":"<echo>","message":"success","method":"thing.lan.prefix.get","version":"1.0"}
   ```
   *(This is the request the device gets **stuck on** with a dumb broker.)*
6. Device `PUBLISH /ext/ntp/<PK>/<DN>/request` `{"deviceSendTime":"<t>"}`
   → **reply** `/ext/ntp/<PK>/<DN>/response`:
   `{"deviceSendTime":"<echo>","serverSendTime":"<now_ms>","serverRecvTime":"<now_ms>"}`
   (`<now_ms>` = current epoch milliseconds as a string.)
7. Device `PUBLISH .../thing/awss/enrollee/match` (a Wi-Fi-provisioning artifact,
   seen right after a fresh (re)bind) → **reply** `.../thing/awss/enrollee/match_reply`:
   `{"code":200,"data":{},"id":<echo>,...}`
8. Ongoing `.../thing/log/post` (diagnostic logs) → no reply needed.
9. The device also subscribes to `post_reply`, so it's polite to answer each of
   its own `.../thing/event/property/post` with a `.../post_reply` `{"code":200,...}`.

**Nothing here requires cloud-side crypto.** `lan/prefix` is a fixed record you
captured; NTP and the acks are synthesised. In our local emulator those values
still make the device happy even though we don't use Alibaba's LAN comms channel
at all — the device just needs a well-formed reply to unblock its boot state
machine.

---

## 7. Command routing gotcha (server-side subscriptions)

Notice in §6 the device **only subscribes to `.../thing/event/+/post_reply`**. It
**never subscribes to its command topic** `.../thing/service/#`. On Alibaba, the
cloud performs a *server-side subscription* and pushes commands down. A plain
broker does no such thing, so your `property/set` publishes go nowhere.

**Fix:** right after the device's `CONNACK`, have the proxy **inject a SUBSCRIBE**
for `/sys/<PK>/<DN>/thing/service/#` onto the device's broker session, and
**swallow the resulting SUBACK** so the device's SDK doesn't see an unsolicited
reply. Use a distinctive packet-id for your injected SUBSCRIBE so you only
swallow *your* SUBACK, not the device's own (`post_reply`) one.

---

## 8. Architecture A — transparent cloud-relay (capture + fallback)

Terminate the device TLS, recover the real cloud IP (`SO_ORIGINAL_DST`), reuse the
captured SNI, re-originate TLS to the **real** cloud, and relay bytes **verbatim**
in both directions while logging the decoded MQTT. This is how you capture §6, and
it's a fine fallback that keeps the vendor app working (the device is genuinely
still on the cloud). You can additionally *tee* telemetry to your own broker and
*inject* commands toward the device. Downside: still internet-dependent.

Minimal capture proxy (per-connection; threads for each direction):

```python
import socket, ssl, struct, threading, time

def original_dst(s):
    raw = s.getsockopt(socket.SOL_IP, 80, 16)
    return socket.inet_ntoa(raw[4:8]), struct.unpack("!H", raw[2:4])[0]

def pump(src, dst, tag, logf):
    while True:
        data = src.recv(4096)
        if not data: break
        dst.sendall(data)                 # relay verbatim
        logf.write(f"{time.time():.0f} {tag} {data.hex()}\n"); logf.flush()
    for s in (src, dst):
        try: s.shutdown(socket.SHUT_RDWR)
        except OSError: pass

def handle(cli_raw, logf):
    cloud_ip, cloud_port = original_dst(cli_raw)
    sni = {"n": None}
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.load_cert_chain("fake.crt", "fake.key")
    sctx.set_ciphers("ALL:@SECLEVEL=0")
    sctx.sni_callback = lambda s, n, c: sni.__setitem__("n", n)
    cli = sctx.wrap_socket(cli_raw, server_side=True)          # device side

    cctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)             # real-cloud side
    cctx.check_hostname = False; cctx.verify_mode = ssl.CERT_NONE
    cctx.set_ciphers("ALL:@SECLEVEL=0")
    up = cctx.wrap_socket(socket.create_connection((cloud_ip, cloud_port), 15),
                          server_hostname=sni["n"])
    threading.Thread(target=pump, args=(cli, up, "DEV->CLOUD", logf)).start()
    threading.Thread(target=pump, args=(up, cli, "CLOUD->DEV", logf)).start()
```

Add MQTT packet framing to `pump()` to pretty-print PUBLISH topics/payloads (parse
the fixed header's remaining-length varint; for PUBLISH read the 2-byte topic
length, then topic, then payload). That log *is* your §6 capture.

---

## 9. Architecture B — pure-local (the goal)

Terminate the device TLS and relay **plaintext MQTT to your own broker**. Add two
behaviours learned above:

1. **Inject the command SUBSCRIBE** after CONNACK (§7).
2. **Answer the boot handshake** (§6) by watching the device's PUBLISHes and
   writing synthesised reply PUBLISHes straight back to the device socket. (The
   device isn't subscribed to the `*_reply` topics, so the broker can't deliver
   them — the proxy must originate them itself.)

No cloud, no internet. Reference implementation (condensed; fill in the
placeholders with your captured values):

```python
import asyncio, ssl, struct, json, time

PK, DN   = "<PK>", "<DN>"
BASE     = f"/sys/{PK}/{DN}"
BROKER   = ("<BROKER_IP>", 1883)
CMD_SUB  = f"{BASE}/thing/service/#"
OUR_PID  = 0xF001                          # so we only swallow our own SUBACK
LAN_PREFIX_DATA = {"deviceSecret": "<DEVICE_SECRET>", "prefix": "<LAN_PREFIX>",
                   "productKey": PK, "deviceName": DN}

def enc_len(n):
    out = bytearray()
    while True:
        d = n % 128; n //= 128
        out.append(d | (0x80 if n else 0))
        if not n: return bytes(out)

def mk_subscribe(topic, pid):
    tb = topic.encode()
    p = struct.pack("!H", pid) + struct.pack("!H", len(tb)) + tb + b"\x00"
    return bytes([0x82]) + enc_len(len(p)) + p

def mk_publish(topic, payload):            # QoS0
    tb, pb = topic.encode(), payload.encode()
    v = struct.pack("!H", len(tb)) + tb + pb
    return bytes([0x30]) + enc_len(len(v)) + v

def iter_packets(buf):                     # -> [(hdr_byte, body)], leftover
    i, n, out = 0, len(buf), []
    while i < n:
        b0, mult, val, j = buf[i], 1, 0, i + 1
        while True:
            if j >= n: return out, buf[i:]
            d = buf[j]; val += (d & 0x7f) * mult; j += 1
            if not d & 0x80: break
            mult *= 128
        end = j + val
        if end > n: return out, buf[i:]
        out.append((b0, buf[j:end])); i = end
    return out, b""

def echo_id(payload):
    try: return json.loads(payload).get("id", "0")
    except Exception: return "0"

def boot_reply(topic, payload):
    ok = lambda method: json.dumps({"code":200,"data":{},"id":echo_id(payload),
                                    "message":"success","method":method,"version":"1.0"})
    if topic.endswith("/thing/lan/prefix/get"):
        return mk_publish(f"{BASE}/thing/lan/prefix/get_reply", json.dumps(
            {"code":200,"data":LAN_PREFIX_DATA,"id":echo_id(payload),
             "message":"success","method":"thing.lan.prefix.get","version":"1.0"}))
    if topic.endswith("/thing/deviceinfo/update"):
        return mk_publish(f"{BASE}/thing/deviceinfo/update_reply", ok("thing.deviceinfo.update"))
    if topic.endswith("/thing/awss/enrollee/match"):
        return mk_publish(f"{BASE}/thing/awss/enrollee/match_reply", ok("thing.awss.enrollee.match"))
    if topic.endswith("/thing/event/property/post"):
        return mk_publish(f"{BASE}/thing/event/property/post_reply", ok("thing.event.property.post"))
    if topic.startswith("/ext/ntp/") and topic.endswith("/request"):
        try: dst = json.loads(payload).get("deviceSendTime", "0")
        except Exception: dst = "0"
        now = str(int(time.time() * 1000))
        return mk_publish(f"/ext/ntp/{PK}/{DN}/response",
            json.dumps({"deviceSendTime":dst,"serverSendTime":now,"serverRecvTime":now}))
    return None

async def handle(dev_r, dev_w):
    mo_r, mo_w = await asyncio.open_connection(*BROKER)
    lock = asyncio.Lock(); st = {"subbed": False}
    async def dwrite(b):
        async with lock: dev_w.write(b); await dev_w.drain()

    async def dev_to_broker():
        buf = b""
        while (data := await dev_r.read(4096)):
            mo_w.write(data); await mo_w.drain()            # forward verbatim
            buf += data; pkts, buf = iter_packets(buf)
            for b0, body in pkts:
                if b0 >> 4 == 3:                            # PUBLISH from device
                    tlen = (body[0] << 8) | body[1]
                    topic = body[2:2+tlen].decode("utf-8", "replace")
                    payload = body[2+tlen:].decode("utf-8", "replace")
                    rep = boot_reply(topic, payload)
                    if rep: await dwrite(rep)               # synth cloud reply
        mo_w.close()

    async def broker_to_dev():
        buf = b""
        while (data := await mo_r.read(4096)):
            buf += data; pkts, buf = iter_packets(buf); out = bytearray()
            for b0, body in pkts:
                if b0 >> 4 == 9:                            # SUBACK
                    if ((body[0] << 8) | body[1]) == OUR_PID: continue   # swallow ours
                out += bytes([b0]) + enc_len(len(body)) + body
                if b0 >> 4 == 2 and not st["subbed"]:       # CONNACK -> inject cmd SUBSCRIBE
                    st["subbed"] = True
                    mo_w.write(mk_subscribe(CMD_SUB, OUR_PID)); await mo_w.drain()
            if out: await dwrite(bytes(out))
        dev_w.close()

    await asyncio.gather(dev_to_broker(), broker_to_dev())

async def main():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain("fake.crt", "fake.key")
    ctx.minimum_version = ssl.TLSVersion.TLSv1
    ctx.set_ciphers("ALL:@SECLEVEL=0")
    srv = await asyncio.start_server(handle, "0.0.0.0", 8883, ssl=ctx)
    async with srv: await srv.serve_forever()

asyncio.run(main())
```

Keep it alive + re-assert the DNAT with a small supervisor loop, and start it on
boot.

---

## 10. Step-by-step replication

1. **Identify the device**: find its IP/MAC; confirm it dials `:1883` on an
   Alibaba `iot-as-mqtt` endpoint (DNS logs or a quick `tcpdump`).
2. **Stand up the TLS terminator** (§4.3) on a box in the traffic path (a Linux
   router is ideal).
3. **Add the DNAT** (§4.1) to redirect the device to your proxy.
4. **Run the cloud-relay** (§8), then **power-cycle the device** to force a cold
   boot and **capture the full §6 handshake**. Record `<PK>`, `<DN>`,
   `<DEVICE_SECRET>`, `<LAN_PREFIX>`, the login `username`/`password`, and the
   region SNI.
5. **Add the device login to your broker** (`<MQTT_USER>` / `<MQTT_PASS>`), plus a
   normal login for your automation client.
6. **Switch to the pure-local proxy** (§9) with your captured constants; keep the
   DNAT (now pointing device → proxy → *local broker*).
7. **Power-cycle again** and watch the proxy log: you should see it answer
   `lan/prefix/get`, NTP, deviceinfo, awss, and inject the command SUBSCRIBE, then
   the device streams telemetry.
8. **Test control** with a read-only status poll (§5.2), confirm a telemetry post
   comes back, then meter a small change (§11).

---

## 11. Behavioural findings (measured)

- **Heads must be started several seconds apart.** Fire both start-commands
  back-to-back and the device drops the second. ~5–6 s spacing is reliable.
- **`seq` must increment** each command or the device dedups it.
- **The device auto-stops at the commanded volume.** In a metered start the two
  heads' `remaining` counters tick down to 0 and the run-flag flips `01 → 00` at
  target — no explicit stop needed. This makes a metered change self-terminating.
- **Flow rate is ~880–900 mL/min per head** on the unit tested (measure yours from
  the telemetry: Δtransferred / Δt during steady state).
- **MQTT STOP (`ACT=00`) is not a 100% reliable mid-run abort.** Send a short
  burst if you need to abort early. The only *guaranteed* stop is cutting mains
  power — but that forces a cold boot (see below), so treat it as a last resort.
- **A cold boot requires the §6 replies.** Without the local emulator the device
  wedges re-requesting `thing.lan.prefix.get` and never streams telemetry. This is
  also why reflexively cutting power is the main failure mode: every power cut is a
  cold boot.

---

## 12. Safety notes (aquarium context, generic)

- A peristaltic dosing head is happy running dry, and a small water changer moves
  little volume relative to a tank, so a runaway or empty-reservoir change is
  low-consequence — **don't reflex-cut power**; stop via MQTT and alert. Reserve a
  power cut for "device has ignored MQTT for N minutes".
- Because the pump auto-stops at volume, prefer **metered starts** over
  run-until-stop for anything unattended, and add an independent runtime backstop
  (a timer, or a level sensor) as defence in depth.
- Validate one supervised change end-to-end before enabling any automation.

---

## 13. Gotchas

- TLS is on **1883**, not 8883. If you DNAT to a broker's *real* TLS port, an
  ECDSA Let's-Encrypt cert will fail cipher negotiation with the ESP — that's why
  we terminate TLS ourselves with an **RSA** cert and `@SECLEVEL=0`.
- The device does **server-side subscriptions** — inject the command SUBSCRIBE or
  commands silently go nowhere.
- The idle telemetry post and the running post are **different shapes**; only
  parse volumes from a post whose run-flag byte is set.
- When killing the proxy from a shell one-liner, don't `pkill -f <pattern>` — it
  matches your own shell's argv and kills your session. Use pidfiles or `pkill -x`.
- After a router firmware update, re-assert the DNAT and any boot service.

---

*Written up from a working deployment. Substitute your own captured constants;
nothing device-specific is included here.*
