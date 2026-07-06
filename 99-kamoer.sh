#!/bin/sh
# on_boot hook: start the Kamoer X2SR local-control supervisor if not already running.
pgrep -f /data/kamoer/run.sh >/dev/null 2>&1 || setsid /data/kamoer/run.sh >/dev/null 2>&1 </dev/null &
