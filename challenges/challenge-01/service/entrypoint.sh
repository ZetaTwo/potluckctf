#!/usr/bin/env sh

set -m

cleanup() {
  trap "" INT TERM EXIT
  kill $(jobs -p) 2>/dev/null || true
  rm -rf "${socks}"
  exit 0
}

socks="$(mktemp -d)"
trap cleanup INT TERM EXIT

echo
echo '-------------------------------------------------------------------------'
echo "booting! please wait ~30 seconds"
echo "you should have a shell once Network Unreachable/Connection Refused stops"
echo "good luck!"
echo '-------------------------------------------------------------------------'
echo

qemu-system-x86_64 -accel kvm -display none -serial unix:"${socks}/entrypoint",server -drive "file=/cake-of-paranoia-with-flag,format=qcow2" -machine q35,usb=off,dump-guest-core=off,hpet=off,acpi=on -m 1G -snapshot & </dev/null >&/dev/null

while ! socat -s - unix-connect:"${socks}/entrypoint"; do
  sleep .5
done
