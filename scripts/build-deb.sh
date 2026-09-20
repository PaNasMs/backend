#!/bin/sh
set -eu
[ "$#" = 1 ] || { echo 'Usage: scripts/build-deb.sh PATH_TO_FRONTEND_DIST' >&2; exit 1; }
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
assets=$(CDPATH= cd -- "$1" && pwd)
[ -f "$assets/index.html" ] || { echo 'Build frontend first' >&2; exit 1; }
cd "$repo"
arch=$(dpkg --print-architecture)
[ "$(go env GOARCH)" = "$(go env GOHOSTARCH)" ] || { echo 'Use native build or an explicitly configured sysroot' >&2; exit 1; }
stage=$(mktemp -d)
trap 'rm -rf -- "$stage"' EXIT HUP INT TERM
mkdir -p dist "$stage/DEBIAN" "$stage/usr/lib/ostojaos" "$stage/usr/share/ostojaos/ui" "$stage/usr/lib/systemd/system" "$stage/etc/pam.d" "$stage/usr/sbin"
go build -buildvcs=false -trimpath -o "$stage/usr/lib/ostojaos/ostojaos-core" ./cmd/ostojaos-core
go build -buildvcs=false -trimpath -tags pam -o "$stage/usr/lib/ostojaos/ostojaos-agent" ./cmd/ostojaos-agent
install -d "$stage/usr/share/doc/ostojaos-prototype"
install -m 0644 LICENSE "$stage/usr/share/doc/ostojaos-prototype/LICENSE"
install -m 0644 NOTICE "$stage/usr/share/doc/ostojaos-prototype/copyright"
cp -R "$assets/." "$stage/usr/share/ostojaos/ui/"
install -d "$stage/usr/lib/ostojaos/management" "$stage/etc/ostojaos/module-keys"
install -m 0644 packaging/ostojaos-local.pem packaging/ostojaos-ci.pem "$stage/etc/ostojaos/module-keys/"
install -m 0644 management/*.py "$stage/usr/lib/ostojaos/management/"
install -m 0644 packaging/profile-keys.py "$stage/usr/lib/ostojaos/profile-keys.py"
install -m 0755 packaging/start-agent "$stage/usr/lib/ostojaos/start-agent"
install -m 0755 packaging/ostojaos-uninstall "$stage/usr/sbin/ostojaos-uninstall"
install -m 0755 packaging/ostojaos-inspect-hardware "$stage/usr/sbin/ostojaos-inspect-hardware"
install -m 0755 packaging/ostojaos-configure "$stage/usr/sbin/ostojaos-configure"
install -m 0644 packaging/pam "$stage/etc/pam.d/ostojaos"
install -d "$stage/usr/lib/udev/rules.d"
install -m 0644 packaging/99-ostojaos-filesystems.rules "$stage/usr/lib/udev/rules.d/"
install -m 0644 packaging/*.service packaging/*.timer "$stage/usr/lib/systemd/system/"
for script in preinst postinst prerm postrm; do install -m 0755 "packaging/$script" "$stage/DEBIAN/$script"; done
printf '/etc/pam.d/ostojaos\n' > "$stage/DEBIAN/conffiles"
cat > "$stage/DEBIAN/control" <<CONTROL
Package: ostojaos-prototype
Version: 0.2.1
Section: admin
Priority: optional
Architecture: $arch
Maintainer: OstojaOS local development
Depends: libc6, libpam0g, libpam-runtime, systemd, adduser, openssl, util-linux, udev, python3, python3-dbus, iproute2, iw, dnsmasq-base, nftables, openssh-client, passwd, mdadm, parted, e2fsprogs, dosfstools, exfatprogs, xfsprogs, btrfs-progs, cryptsetup-bin, cifs-utils, nfs-common, nfs-kernel-server, smartmontools, psmisc, hdparm, rsync
Description: OstojaOS management panel, PAM login and Linux system operations
CONTROL
dpkg-deb --root-owner-group --build "$stage" "dist/ostojaos-prototype_0.2.1_${arch}.deb"
