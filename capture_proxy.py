#!/usr/bin/env python3
# TRANSPARENT capture MITM for the Kamoer X2SR cold-boot handshake.
#   device --TLS:1883--> [DNAT to UDM:8883] --> this proxy --TLS--> REAL Alibaba cloud
# We terminate the device's TLS with the fake RSA cert, recover the real cloud IP
# via SO_ORIGINAL_DST, capture the device's SNI, then re-originate TLS to the real
# cloud and relay bytes both ways VERBATIM (no injection) while decoding+logging
# every MQTT packet. Goal: capture the boot requests (thing.lan.prefix.get, NTP,
# config get) and the cloud's replies to see if they're statically replayable.
import socket, ssl, struct, threading, time, sys

LISTEN_PORT = 8883
CERT = "/data/kamoer/fake.crt"
KEY  = "/data/kamoer/fake.key"
LOG  = "/data/kamoer/capture.log"
SO_ORIGINAL_DST = 80

logf = open(LOG, "a", buffering=1)
def log(msg):
    line = f"{time.strftime('%H:%M:%S')} {msg}"
    logf.write(line + "\n")
    print(line, flush=True)

TYPES = {1:"CONNECT",2:"CONNACK",3:"PUBLISH",4:"PUBACK",5:"PUBREC",6:"PUBREL",
         7:"PUBCOMP",8:"SUBSCRIBE",9:"SUBACK",10:"UNSUBSCRIBE",11:"UNSUBACK",
         12:"PINGREQ",13:"PINGRESP",14:"DISCONNECT"}

def iter_packets(buf):
    i, n, out = 0, len(buf), []
    while i < n:
        b0 = buf[i]; typ = b0 >> 4
        mult, val, j = 1, 0, i + 1
        while True:
            if j >= n: return out, buf[i:]
            d = buf[j]; val += (d & 0x7f) * mult; j += 1
            if not (d & 0x80): break
            mult *= 128
        end = j + val
        if end > n: return out, buf[i:]
        out.append((b0, buf[j:end]))   # (header byte, variable+payload)
        i = end
    return out, b""

def decode(direction, b0, body):
    typ = b0 >> 4
    name = TYPES.get(typ, f"?{typ}")
    if typ == 3:  # PUBLISH
        qos = (b0 >> 1) & 3
        tlen = (body[0] << 8) | body[1]
        topic = body[2:2+tlen].decode("utf-8", "replace")
        off = 2 + tlen
        pid = ""
        if qos > 0:
            pid = f" pid={(body[off]<<8)|body[off+1]}"; off += 2
        payload = body[off:]
        try: ptxt = payload.decode("utf-8")
        except Exception: ptxt = payload.hex()
        log(f"{direction} PUBLISH qos={qos}{pid} topic={topic}")
        log(f"{direction}     payload={ptxt}")
    elif typ == 1:  # CONNECT
        log(f"{direction} CONNECT ({len(body)}B) hex={body.hex()}")
    elif typ == 8:  # SUBSCRIBE
        log(f"{direction} SUBSCRIBE hex={body.hex()}")
    else:
        log(f"{direction} {name} ({len(body)}B)" + (f" hex={body.hex()}" if len(body) < 24 else ""))

def pump(src, dst, direction):
    buf = b""
    try:
        while True:
            data = src.recv(4096)
            if not data: break
            dst.sendall(data)
            buf += data
            pkts, buf = iter_packets(buf)
            for b0, body in pkts:
                try: decode(direction, b0, body)
                except Exception as e: log(f"{direction} decode-err {e} b0={b0:02x} hex={body.hex()[:80]}")
    except Exception as e:
        log(f"{direction} pump end: {e}")
    finally:
        for s in (src, dst):
            try: s.shutdown(socket.SHUT_RDWR)
            except Exception: pass

def original_dst(sock):
    raw = sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
    port = struct.unpack("!H", raw[2:4])[0]
    ip = socket.inet_ntoa(raw[4:8])
    return ip, port

def handle(cli_raw, addr):
    sni = {"name": None}
    try:
        cloud_ip, cloud_port = original_dst(cli_raw)
    except Exception as e:
        log(f"NO SO_ORIGINAL_DST ({e}) — is the DNAT in place?"); cli_raw.close(); return
    log(f"--- device {addr} -> real cloud {cloud_ip}:{cloud_port} ---")

    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.load_cert_chain(CERT, KEY)
    try: sctx.minimum_version = ssl.TLSVersion.TLSv1
    except Exception: pass
    try: sctx.set_ciphers("ALL:@SECLEVEL=0")
    except Exception: pass
    def sni_cb(s, name, ctx): sni["name"] = name
    sctx.sni_callback = sni_cb

    try:
        cli = sctx.wrap_socket(cli_raw, server_side=True)
    except Exception as e:
        log(f"device TLS handshake failed: {e}"); cli_raw.close(); return
    log(f"device TLS up. SNI={sni['name']!r} cipher={cli.cipher()}")

    # upstream to the REAL cloud
    cctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    cctx.check_hostname = False
    cctx.verify_mode = ssl.CERT_NONE
    try: cctx.set_ciphers("ALL:@SECLEVEL=0")
    except Exception: pass
    try:
        up_raw = socket.create_connection((cloud_ip, cloud_port), timeout=15)
        up = cctx.wrap_socket(up_raw, server_hostname=(sni["name"] or None))
    except Exception as e:
        log(f"UPSTREAM connect/TLS failed to {cloud_ip}:{cloud_port}: {e}")
        try: cli.close()
        except Exception: pass
        return
    log(f"upstream TLS up -> {cloud_ip}:{cloud_port} SNI={sni['name']!r} cipher={up.cipher()}")

    t1 = threading.Thread(target=pump, args=(cli, up, "DEV->CLOUD"), daemon=True)
    t2 = threading.Thread(target=pump, args=(up, cli, "CLOUD->DEV"), daemon=True)
    t1.start(); t2.start()
    t1.join(); t2.join()
    log(f"--- session {addr} closed ---")

def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", LISTEN_PORT))
    srv.listen(8)
    log(f"capture proxy listening on :{LISTEN_PORT}")
    while True:
        cli_raw, addr = srv.accept()
        threading.Thread(target=handle, args=(cli_raw, addr), daemon=True).start()

if __name__ == "__main__":
    main()
