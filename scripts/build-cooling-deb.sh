#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
stage=$(mktemp -d)
trap 'rm -rf -- "$stage"' EXIT HUP INT TERM
mkdir -p "$stage/DEBIAN" "$stage/usr/lib/ostojaos-cooling" "$stage/usr/lib/systemd/system" "$stage/usr/sbin" dist
install -m644 cooling/controller.py "$stage/usr/lib/ostojaos-cooling/controller.py"
install -m644 cooling/ostojaos-cooling.service "$stage/usr/lib/systemd/system/"
install -m755 cooling/ostojaos-cooling-configure "$stage/usr/sbin/"
install -m755 cooling/preinst "$stage/DEBIAN/preinst"
install -m755 cooling/postinst "$stage/DEBIAN/postinst"
install -m755 cooling/prerm "$stage/DEBIAN/prerm"
cat > "$stage/DEBIAN/control" <<CONTROL
Package: ostojaos-cooling
Version: 0.2.0
Architecture: all
Maintainer: OstojaOS local development
Depends: python3, python3-libgpiod, smartmontools, raspi-utils, systemd
Description: Independent GPIO27 disk cooling for the verified OstojaOS hardware
CONTROL
dpkg-deb --root-owner-group --build "$stage" dist/ostojaos-cooling_0.2.0_all.deb
