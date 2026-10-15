#!/bin/sh
# CI: the reproducer must show the wrong answer with SpiceDB's dispatch
# cache on ($CACHED) and the right one with it off ($UNCACHED).
set -eu
here=$(dirname "$0")
on=$(SPICEDB=$CACHED "$here/repro.sh" | tail -1)
off=$(SPICEDB=$UNCACHED "$here/repro.sh" | tail -1)
echo "cache on:  $on"
echo "cache off: $off"
case "$on" in *HAS_PERMISSION) ;; *) echo "expected the cached answer to be wrong"; exit 1 ;; esac
case "$off" in *NO_PERMISSION) ;; *) echo "expected the uncached answer to be right"; exit 1 ;; esac
