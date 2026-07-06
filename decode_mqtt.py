#!/usr/bin/env python3
import re, sys, json

PATH = sys.argv[1] if len(sys.argv) > 1 else "mitm2.log"
dev2brk = bytearray()   # '>'  device -> broker
brk2dev = bytearray()   # '<'  broker -> device (commands live here)

direction = None
with open(PATH, "r", errors="replace") as f:
    for line in f:
        if re.match(r'^[<>] \d{4}/', line):
            direction = line[0]
            continue
        if line.startswith(' '):
            # split hex column from ascii column (separated by 2+ spaces)
            parts = re.split(r' {2,}', line.rstrip('\n'))
            hexpart = None
            for p in parts:
                if re.fullmatch(r'(?:[0-9a-fA-F]{2} ?)+', p.strip()):
                    hexpart = p.strip(); break
            if not hexpart:
                continue
            try:
                bs = bytes(int(x, 16) for x in hexpart.split())
            except ValueError:
                continue
            (dev2brk if direction == '>' else brk2dev).extend(bs)

TYPES = {1:"CONNECT",2:"CONNACK",3:"PUBLISH",4:"PUBACK",5:"PUBREC",6:"PUBREL",
         7:"PUBCOMP",8:"SUBSCRIBE",9:"SUBACK",10:"UNSUBSCRIBE",11:"UNSUBACK",
         12:"PINGREQ",13:"PINGRESP",14:"DISCONNECT"}

def rd_len(b, i):
    mult=1; val=0
    while True:
        d=b[i]; i+=1; val += (d & 0x7f)*mult
        if not (d & 0x80): break
        mult*=128
    return val, i

def show(payload):
    try:
        t = payload.decode('utf-8')
        if all(31 < ord(c) < 127 or c in '\r\n\t{}[]":,./_-&|=+ ' for c in t):
            return t
    except Exception:
        pass
    return payload.hex()

def parse(stream, label):
    print(f"\n{'='*70}\n{label}  ({len(stream)} bytes)\n{'='*70}")
    i=0; n=len(stream)
    while i < n:
        b0=stream[i]; typ=b0>>4; flags=b0&0xf
        if typ not in TYPES:
            print(f"  [desync @ {i}: byte {b0:#x}] stopping"); break
        try:
            rl, j = rd_len(stream, i+1)
        except IndexError:
            break
        body = stream[j:j+rl]; i = j+rl
        name = TYPES[typ]
        if typ==3:  # PUBLISH
            tl=(body[0]<<8)|body[1]; topic=body[2:2+tl].decode('utf-8','replace')
            k=2+tl; qos=(flags>>1)&3
            if qos>0: k+=2
            pl=body[k:]
            print(f"\n  PUBLISH  topic={topic}")
            print(f"           payload={show(pl)}")
        elif typ==8:  # SUBSCRIBE
            k=2; subs=[]
            while k < len(body):
                tl=(body[k]<<8)|body[k+1]; t=body[k+2:k+2+tl].decode('utf-8','replace')
                k+=2+tl+1; subs.append(t)
            print(f"\n  SUBSCRIBE -> {subs}")
        elif typ==1:
            print(f"\n  CONNECT  {show(body)[:200]}")
        elif typ in (2,4,9):
            print(f"  {name} {body.hex()}")
        # ignore ping noise

parse(brk2dev, "BROKER -> DEVICE  (commands from app)")
parse(dev2brk, "DEVICE -> BROKER  (status / replies)")
