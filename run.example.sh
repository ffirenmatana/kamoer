#!/bin/sh
# Kamoer X2SR PURE-LOCAL supervisor (persistent, runs on the UDM).
# - keeps the TLS->plaintext proxy + boot-handshake emulator (kamoer_local.py) alive
# - re-asserts the DNAT (device -> UDM:8883) every 60s in case UniFi rebuilds the firewall
# No Kamoer cloud / no internet dependency: kamoer_local.py answers the device's cold-boot
# requests (lan.prefix.get / NTP / deviceinfo / awss) locally and injects the command SUBSCRIBE.
echo $$ > /data/kamoer/run.pid
CRT=/data/kamoer/fake.crt; KEY=/data/kamoer/fake.key
DEV=<DEVICE_IP>
RULE="-s $DEV -p tcp --dport 1883 -j DNAT --to-destination <ROUTER_IP>:8883"
[ -f "$CRT" ] || openssl req -x509 -newkey rsa:2048 -keyout "$KEY" -out "$CRT" \
  -days 3650 -nodes -subj "/CN=iot.kamoer.com" 2>/dev/null
# DNAT watchdog (idempotent; -C checks existence before adding)
( while true; do
    iptables -t nat -C PREROUTING $RULE 2>/dev/null || iptables -t nat -I PREROUTING 1 $RULE
    sleep 60
  done ) &
# proxy supervisor
while true; do
  python3 /data/kamoer/kamoer_local.py >> /data/kamoer/local.out 2>&1
  sleep 2
done
