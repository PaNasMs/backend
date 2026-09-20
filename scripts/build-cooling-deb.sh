#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
stage=$(mktemp -d)
trap 'rm -rf -- "$stage"' EXIT HUP INT TERM
mkdir -p "$stage/DEBIAN" "$stage/usr/lib/panasms-cooling" "$stage/usr/lib/systemd/system" "$stage/usr/sbin" dist
install -m644 cooling/controller.py "$stage/usr/lib/panasms-cooling/controller.py"
install -m644 cooling/panasms-cooling.service "$stage/usr/lib/systemd/system/"
install -m755 cooling/panasms-cooling-configure "$stage/usr/sbin/"
install -m755 cooling/preinst "$stage/DEBIAN/preinst"
install -m755 cooling/postinst "$stage/DEBIAN/postinst"
install -m755 cooling/prerm "$stage/DEBIAN/prerm"
cat > "$stage/DEBIAN/control" <<CONTROL
Package: panasms-cooling
Version: 0.2.0
Architecture: all
Maintainer: PaNasMs local development
Depends: python3, python3-libgpiod, smartmontools, raspi-utils, systemd
Description: Independent GPIO27 disk cooling for the verified PaNasMs hardware
CONTROL
dpkg-deb --root-owner-group --build "$stage" dist/panasms-cooling_0.2.0_all.deb
