#!/usr/bin/env python3
# PURE-LOCAL proxy + mini cloud-emulator for the Kamoer X2SR.
#   device --TLS:1883--> [DNAT to UDM:8883] --> this proxy --plaintext--> mosquitto <BROKER_IP>:1883
#
# Two jobs beyond plain relaying, both learned from the cold-boot capture:
#  1) COMMAND ROUTING: the device only SUBSCRIBEs to .../thing/event/+/post_reply, never to
#     its command topic (Alibaba uses server-side subs). So after CONNACK we inject a
#     SUBSCRIBE for .../thing/service/# on the device's broker session and swallow *only*
#     our own SUBACK (matched by packet-id) so HA's property/set publishes reach the device.
#  2) BOOT HANDSHAKE: the device blocks at boot until the "cloud" answers a few requests.
#     Mosquitto won't, so this proxy synthesizes those replies and injects them straight to
#     the device socket (the device is NOT subscribed to the *_reply topics, so they can't
#     come via the broker). Replies captured from the real cloud: lan/prefix/get (static),
#     NTP (timestamp), deviceinfo/update (ack), awss/enrollee/match (ack). We also ack the
#     device's own event/property/post so its SDK is happy.
import asyncio, ssl, logging, struct, json, time

PK = "<PK>"
DN = "<DN>"
BASE = f"/sys/{PK}/{DN}"
MOSQ_HOST, MOSQ_PORT = "<BROKER_IP>", 1883
LISTEN_PORT = 8883
CERT, KEY = "/data/kamoer/fake.crt", "/data/kamoer/fake.key"
CMD_SUB_TOPIC = f"{BASE}/thing/service/#"
OUR_SUB_PID = 0xF001          # distinct so we only swallow our own SUBACK

# static reply captured from the real Alibaba cloud (per-device constants)
LAN_PREFIX_DATA = {"deviceSecret": "<DEVICE_SECRET>",
                   "prefix": "<LAN_PREFIX>", "productKey": PK, "deviceName": DN}

logging.basicConfig(filename="/data/kamoer/local.log", level=logging.INFO,
                    format="%(asctime)s %(message)s")
log = logging.getLogger("kamoer").info

def enc_len(n):
    out = bytearray()
    while True:
        d = n % 128; n //= 128
        if n > 0: d |= 0x80
        out.append(d)
        if n == 0: break
    return bytes(out)

def mk_subscribe(topic, pid):
    tb = topic.encode()
    payload = struct.pack("!H", pid) + struct.pack("!H", len(tb)) + tb + b"\x00"
    return bytes([0x82]) + enc_len(len(payload)) + payload

def mk_publish(topic, payload_str):        # QoS0 (matches how the cloud sent replies)
    tb = topic.encode(); pb = payload_str.encode()
    var = struct.pack("!H", len(tb)) + tb + pb
    return bytes([0x30]) + enc_len(len(var)) + var

CMD_SUBPKT = mk_subscribe(CMD_SUB_TOPIC, OUR_SUB_PID)

def iter_packets(buf):
    """(list of (header_byte, variable+payload bytes, full_packet_bytes), leftover)."""
    i, n, out = 0, len(buf), []
    while i < n:
        b0 = buf[i]
        mult, val, j = 1, 0, i + 1
        while True:
            if j >= n: return out, buf[i:]
            d = buf[j]; val += (d & 0x7f) * mult; j += 1
            if not (d & 0x80): break
            mult *= 128
        end = j + val
        if end > n: return out, buf[i:]
        out.append((b0, buf[j:end], buf[i:end]))
        i = end
    return out, b""

def parse_publish(body):
    tlen = (body[0] << 8) | body[1]
    topic = body[2:2+tlen].decode("utf-8", "replace")
    off = 2 + tlen
    # (we only synthesize replies for QoS0 requests; if QoS>0 there'd be a pid here,
    #  but every request we answer was seen at QoS0 — still, be tolerant)
    payload = body[off:]
    return topic, payload

def echo_id(payload):
    try:
        return json.loads(payload.decode("utf-8")).get("id", "0")
    except Exception:
        return "0"

def boot_reply(topic, payload):
    """Return a reply PUBLISH (bytes) to inject to the device, or None."""
    if topic.endswith("/thing/lan/prefix/get"):
        r = {"code":200,"data":LAN_PREFIX_DATA,"id":echo_id(payload),
             "message":"success","method":"thing.lan.prefix.get","version":"1.0"}
        return mk_publish(f"{BASE}/thing/lan/prefix/get_reply", json.dumps(r))
    if topic.endswith("/thing/deviceinfo/update"):
        r = {"code":200,"data":{},"id":echo_id(payload),
             "message":"success","method":"thing.deviceinfo.update","version":"1.0"}
        return mk_publish(f"{BASE}/thing/deviceinfo/update_reply", json.dumps(r))
    if topic.endswith("/thing/awss/enrollee/match"):
        r = {"code":200,"data":{},"id":echo_id(payload),
             "message":"success","method":"thing.awss.enrollee.match","version":"1.0"}
        return mk_publish(f"{BASE}/thing/awss/enrollee/match_reply", json.dumps(r))
    if topic.endswith("/thing/event/property/post"):
        r = {"code":200,"data":{},"id":echo_id(payload),
             "message":"success","method":"thing.event.property.post","version":"1.0"}
        return mk_publish(f"{BASE}/thing/event/property/post_reply", json.dumps(r))
    if topic.startswith("/ext/ntp/") and topic.endswith("/request"):
        try: dst = json.loads(payload.decode("utf-8")).get("deviceSendTime","0")
        except Exception: dst = "0"
        now = str(int(time.time() * 1000))
        r = {"deviceSendTime":dst, "serverSendTime":now, "serverRecvTime":now}
        return mk_publish(f"/ext/ntp/{PK}/{DN}/response", json.dumps(r))
    return None

async def handle(dev_r, dev_w):
    peer = dev_w.get_extra_info("peername")
    try:
        mo_r, mo_w = await asyncio.open_connection(MOSQ_HOST, MOSQ_PORT)
    except Exception as e:
        log(f"mosq connect failed: {e}"); dev_w.close(); return
    log(f"device connected {peer}")
    dev_lock = asyncio.Lock()          # serialize writes to the device socket
    st = {"subbed": False}

    async def dev_write(data):
        async with dev_lock:
            dev_w.write(data); await dev_w.drain()

    async def dev_to_mosq():
        buf = b""
        try:
            while True:
                data = await dev_r.read(4096)
                if not data: break
                mo_w.write(data); await mo_w.drain()      # forward verbatim to broker
                buf += data
                pkts, buf = iter_packets(buf)
                for b0, body, _full in pkts:
                    if b0 >> 4 == 3:                      # PUBLISH from device
                        try:
                            topic, payload = parse_publish(body)
                            rep = boot_reply(topic, payload)
                            if rep:
                                await dev_write(rep)
                                log(f"replied to {topic}")
                        except Exception as e:
                            log(f"boot_reply err: {e}")
        except Exception as e:
            log(f"dev_to_mosq end: {e}")
        finally:
            try: mo_w.close()
            except Exception: pass

    async def mosq_to_dev():
        buf = b""
        try:
            while True:
                data = await mo_r.read(4096)
                if not data: break
                buf += data
                pkts, buf = iter_packets(buf)
                out = bytearray()
                for b0, body, full in pkts:
                    typ = b0 >> 4
                    if typ == 9:                          # SUBACK
                        pid = (body[0] << 8) | body[1]
                        if pid == OUR_SUB_PID:
                            log("swallowed our SUBACK"); continue
                        out += full                       # device's own SUBACK -> forward
                        continue
                    out += full
                    if typ == 2 and not st["subbed"]:     # CONNACK -> inject command SUBSCRIBE
                        st["subbed"] = True
                        mo_w.write(CMD_SUBPKT); await mo_w.drain()
                        log(f"injected SUBSCRIBE -> {CMD_SUB_TOPIC}")
                if out:
                    await dev_write(bytes(out))
        except Exception as e:
            log(f"mosq_to_dev end: {e}")
        finally:
            try: dev_w.close()
            except Exception: pass

    await asyncio.gather(dev_to_mosq(), mosq_to_dev())
    log(f"device disconnected {peer}")

async def main():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT, KEY)
    try: ctx.minimum_version = ssl.TLSVersion.TLSv1
    except Exception: pass
    try: ctx.set_ciphers("ALL:@SECLEVEL=0")
    except Exception: pass
    srv = await asyncio.start_server(handle, "0.0.0.0", LISTEN_PORT, ssl=ctx)
    log("local proxy listening on :8883")
    async with srv:
        await srv.serve_forever()

asyncio.run(main())
