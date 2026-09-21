#!/bin/sh
set -eu
[ "$#" = 1 ] || { echo 'Usage: scripts/build-deb.sh PATH_TO_FRONTEND_DIST' >&2; exit 1; }
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
assets=$(CDPATH= cd -- "$1" && pwd)
[ -f "$assets/index.html" ] || { echo 'Build frontend first' >&2; exit 1; }
cd "$repo"
version=${PANASMS_PACKAGE_VERSION:-$(cat VERSION)}
dpkg --validate-version "$version"
arch=$(dpkg --print-architecture)
[ "$(go env GOARCH)" = "$(go env GOHOSTARCH)" ] || { echo 'Use native build or an explicitly configured sysroot' >&2; exit 1; }
stage=$(mktemp -d)
trap 'rm -rf -- "$stage"' EXIT HUP INT TERM
mkdir -p dist "$stage/DEBIAN" "$stage/usr/lib/panasms" "$stage/usr/share/panasms/ui" "$stage/usr/lib/systemd/system" "$stage/etc/pam.d" "$stage/usr/sbin"
go build -buildvcs=false -trimpath -o "$stage/usr/lib/panasms/panasms-core" ./cmd/panasms-core
go build -buildvcs=false -trimpath -tags pam -o "$stage/usr/lib/panasms/panasms-agent" ./cmd/panasms-agent
go build -buildvcs=false -trimpath -tags pam -o "$stage/usr/lib/panasms/panasms-password" ./cmd/panasms-password
install -d "$stage/usr/share/doc/panasms-prototype"
install -m 0644 LICENSE "$stage/usr/share/doc/panasms-prototype/LICENSE"
install -m 0644 NOTICE "$stage/usr/share/doc/panasms-prototype/copyright"
cp -R "$assets/." "$stage/usr/share/panasms/ui/"
install -d "$stage/usr/share/keyrings"
install -m 0644 packaging/panasms-updates.gpg "$stage/usr/share/keyrings/"
install -d "$stage/usr/lib/panasms/management" "$stage/etc/panasms/module-keys"
install -m 0644 packaging/panasms-local.pem packaging/panasms-ci.pem "$stage/etc/panasms/module-keys/"
install -m 0644 management/*.py "$stage/usr/lib/panasms/management/"
install -m 0644 packaging/sharing-install.py "$stage/usr/lib/panasms/sharing-install.py"
install -m 0644 packaging/profile-keys.py "$stage/usr/lib/panasms/profile-keys.py"
install -m 0755 packaging/start-agent "$stage/usr/lib/panasms/start-agent"
install -m 0755 packaging/panasms-uninstall "$stage/usr/sbin/panasms-uninstall"
install -m 0755 packaging/panasms-inspect-hardware "$stage/usr/sbin/panasms-inspect-hardware"
install -m 0755 packaging/panasms-configure "$stage/usr/sbin/panasms-configure"
install -m 0644 packaging/pam "$stage/etc/pam.d/panasms"
install -d "$stage/usr/lib/udev/rules.d"
install -m 0644 packaging/*.rules "$stage/usr/lib/udev/rules.d/"
install -m 0644 packaging/*.service packaging/*.timer "$stage/usr/lib/systemd/system/"
for script in preinst postinst prerm postrm; do install -m 0755 "packaging/$script" "$stage/DEBIAN/$script"; done
printf '/etc/pam.d/panasms\n' > "$stage/DEBIAN/conffiles"
cat > "$stage/DEBIAN/control" <<CONTROL
Package: panasms-prototype
Version: $version
Section: admin
Priority: optional
Architecture: $arch
Maintainer: PaNasMs local development
Depends: apt, gpgv, dpkg-repack, libc6, libpam0g, libpam-runtime, libpam-modules, libpam-systemd, systemd, adduser, openssl, ca-certificates, util-linux, mount, fdisk, initramfs-tools, udev, usb-modeswitch, python3, python3-dbus, network-manager, wpasupplicant, iproute2, iw, dnsmasq-base, nftables, openssh-client, passwd, mdadm, parted, e2fsprogs, dosfstools, exfatprogs, xfsprogs, btrfs-progs, cryptsetup-bin, cifs-utils, nfs-common, nfs-kernel-server, samba, samba-common-bin, smbclient, acl, smartmontools, psmisc, hdparm, rsync
Description: PaNasMs management panel, PAM login and Linux system operations
CONTROL
dpkg-deb --root-owner-group --build "$stage" "dist/panasms-prototype_${version}_${arch}.deb"
