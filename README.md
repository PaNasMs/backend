# PaNasMs backend

This repository is the Linux server side of [PaNasMs](https://github.com/PaNasMs/panasms)
(Pavlo's NAS Management System). It contains the Go HTTP/WebSocket core, the privileged Go agent
and system helpers, the Python system-management adapters, and the scripts that build the
`panasms-prototype` (core) and `panasms-cooling` Debian packages. The current version is 0.2.15,
the first stable release.

End users install PaNasMs with the one-command installer described on the
[project website](https://panasms.github.io/) and in the
[installation guide](https://panasms.github.io/docs/setup/install/). The installer and update
channels live in [PaNasMs/updates](https://github.com/PaNasMs/updates). Supported systems are
Raspberry Pi OS 13 ARM64, Debian 13 ARM64/AMD64, Ubuntu 24.04 LTS AMD64 and Armbian 26.8 (Debian 13).

## Architecture

- **Core** (`panasms-core`) serves the SPA, the HTTP API, sessions, user preferences, wallpaper,
  notifications and metrics. It runs as the restricted `panasms` service user.
- **Agent** (`panasms-agent`) authenticates users through PAM and runs authorized system
  operations behind a local Unix socket. It keeps its persistent jobs in its own database.
- **System helpers** (`panasms-system-helper`, `panasms-keys`, `panasms-password`,
  `panasms-networkd`) are Go binaries for account, key, password, network and other system
  operations. Some also run as their own systemd services, such as network access and volume
  access.
- **Python adapters** in `management/` call Linux tools for the domains that have not moved to Go.
  Linux stays the source of truth for users, disks, mounts, RAID and network configuration.
- **Installable modules** (Files, Terminal, Cloud Sync, Containers) run as separate services and
  ship as separate signed packages from their own repositories.
- **Cooling** (`panasms-cooling`) is a separate package and service, so removing the panel does
  not stop the disk cooling controller.

The code uses `net/http`, chi, coder/websocket, `database/sql` with SQLite, PAM through cgo, and
systemd. The Go store packages own SQLite schema creation and migrations. There is no sqlc step.

## Source layout

| Path | Contents |
| --- | --- |
| [cmd](cmd) | Entry points for core, agent, cooling and the system helpers |
| [internal](internal) | API, identity, persistence, jobs, metrics, system operations and module integration |
| [management](management) | Python Linux adapters and module installation/catalog logic |
| [api/openapi.yaml](api/openapi.yaml) | Management API contract |
| [api/events.md](api/events.md) | Event WebSocket protocol |
| [packaging](packaging) | Debian hooks, systemd units, udev rules, PAM policy and administration tools |
| [cooling](cooling) | Disk cooling controller packaging and device tree overlay |
| [scripts](scripts) | Package builds, source installation and one-time migrations |
| [tests](tests) | Python tests and integration tests; Go tests live beside their packages |

## Build and test

You need Linux, Go 1.26 or newer, Python 3, a C compiler and PAM development headers
(`libpam0g-dev` on Debian). PAM and SQLite require cgo. The Python tests also need
`python3-pil`, `python3-yaml` and `python3-jsonschema`, and a checkout of
[module-files](https://github.com/PaNasMs/module-files) at `../modules/files`, because
`tests/filesystem_health_test.py` imports its backend. CI uses the same layout.

```sh
make check        # Go tests with the pam tag, go vet, Python unit tests
make check-race   # Go tests with the race detector
make build        # bin/panasms-core, panasms-agent, panasms-system-helper, panasms-keys, panasms-password
```

The test suite uses temporary data. It covers legacy schema adoption, failed and future
migrations, crashes inside migrations and jobs, journal write failures, cooperative cancellation
and job ordering. Physical power loss and hardware controllers need separate acceptance tests on
real hardware.

### Integration tests

`make check-accounts-integration` builds the workers and runs disposable account and PAM tests in
user, mount, PID and network namespaces. It needs user namespaces, `newuidmap`/`newgidmap` with
subordinate UID/GID ranges, PAM headers and the standard account tools. It never modifies host
accounts. Account commands, PAM, keys and home moves or deletion run for real; systemd and storage
discovery use fixtures. The tests compare native queries, plans and recovery reports with the
legacy Python contract.

`make check-network-integration` must run as root on an authorized test host with
NetworkManager. It creates and removes a temporary veth pair to test checkpoint handling and does
not change the management connection.

The native networking hardware tests in `internal/systemops/networknative` are opt-in.
`PANASMS_NATIVE_TEST_WIFI=wlan0` enables radio, scan and access point tests, and
`PANASMS_NATIVE_TEST_UPLINK=end0` enables an isolated veth/NAT test. Run them only as root on an
authorized test host with NetworkManager stopped and a separate way to recover the host. The access
point test checks service readiness, not a client association or DHCP lease.

### Debian packages

Build the [frontend](https://github.com/PaNasMs/frontend) first, then build the packages natively
on the target architecture. The core script refuses to cross-compile.

```sh
sh scripts/build-deb.sh ../frontend/dist
sh scripts/build-cooling-deb.sh
```

The outputs are `dist/panasms-prototype_<version>_<arch>.deb` and
`dist/panasms-cooling_<version>_<arch>.deb`. The core version comes from [VERSION](VERSION) unless
`PANASMS_PACKAGE_VERSION` is set. The cooling version defaults to 0.2.0 unless
`PANASMS_COOLING_VERSION` is set. Both scripts validate the version with `dpkg`. The cooling build
also compiles `pinctrl` and `dtoverlay` from `third_party/raspberrypi-utils`, so it needs `cmake`,
`libfdt-dev` and `device-tree-compiler`.

Pushes to `main` call the shared build workflow in PaNasMs/panasms, which builds ARM64 and AMD64
packages and feeds the testing channel. The
[build guide](https://github.com/PaNasMs/panasms/blob/main/documentation/builds.md) describes the
artifacts, source manifests and validation limits.

## Installation and operation

To install a locally built package on a Debian-based machine:

```sh
sudo apt update
sudo apt install ./panasms-prototype_<version>_<arch>.deb
sudo panasms-configure            # port 80 on a fresh installation
sudo panasms-configure --port 8080
```

Use `apt install`, not `dpkg -i`, so APT downloads the dependencies listed in `Depends` (RAID,
partition, filesystem and SMART tools, Samba and NFS, Wi-Fi tools, PAM and session support). They
install even with `--no-install-recommends`, so the distribution repositories must be reachable.
OpenSSH server is optional. `panasms-configure` without `--port` keeps the existing port. It needs
an existing non-root user in the `sudo` group and does not create an administrator.
`sudo scripts/install-prototype.sh --assets ../frontend/dist [--port PORT] [--disk-fan]` builds and
installs both packages from source in one step.

Administrators can change the HTTP port in Settings > General. The panel rejects occupied and
browser-blocked ports, restarts, and redirects the browser once the new address responds. If
startup fails, it restores the previous port. The port is stored in `/etc/panasms/web.env` and
survives upgrades. `sudo panasms-tls enable [CERTIFICATE KEY]` switches the panel to HTTPS with a
supplied or self-signed certificate, and `sudo panasms-tls disable` switches it back.

| Path | Contents |
| --- | --- |
| `/etc/panasms/panasms.env` | Runtime configuration |
| `/var/lib/panasms` | Core state |
| `/var/lib/panasms-agent` | Agent jobs and state |

Inspect `panasms-core`, `panasms-agent` and, if installed, `panasms-cooling` with `systemctl` and
`journalctl`.

`sudo panasms-uninstall --plan` previews removal. `--remove` removes the panel, and `--purge` also
removes panel-owned state. Panel-published SMB/NFS shares are unpublished. User files, Linux
accounts, RAID arrays, mounts and the cooling package stay. Review the plan before running either
mode.

`scripts/migrate-pinas.py` and `scripts/migrate-ostojaos.py` are one-time migrations for two
specific earlier prototype installations and their backup artifacts. They are not general
installers or upgrade migrations.

## Users, groups and access

The Users section reads local Linux users and groups on every request. Membership in `sudo`
(primary or supplementary) grants administration. Root, service UIDs, non-local accounts and
ambiguous duplicate-UID accounts are visible but protected. Ordinary accounts need explicit panel
access in `/etc/panasms/accounts.json`. Existing sudo users keep bootstrap access. An optional
deployment allowlist can restrict access further. Hiding a control in the UI is not an
authorization boundary; the server validates every operation.

Administrators manage account names, groups, homes, UID, expiry, password aging, forced password
changes, SSH keys and panel/SSH sessions. New accounts get a private home and panel access, with
SSH disabled. Deletion removes only the home by default and keeps shared-folder files. A busy home
returns the blocking processes and services. The panel blocks self-lockout and removal of the last
administrator. A UID change updates home ownership through `usermod`; ownership on other volumes
needs a separate decision.

Passwords follow the host PAM configuration with no extra strength policy. Own-password changes use
the `passwd` PAM stack with the caller's real UID, as `passwd` does. Administrator resets use
`chpasswd`. An expired password must be changed before the panel issues a session. Every session
is rechecked against live Linux access, UID and a revocation epoch. Password resets and access or
membership changes revoke affected sessions.

Ordinary users can use their profile, avatar, language, desktop preferences, read-only system
widgets and Files under their own Linux permissions. They cannot administer storage, network,
modules, users, services or other users' sessions and tasks. Terminal, Cloud Sync and the other
module APIs except Files are administrator-only. Security history records panel sign-ins, profile
changes, session termination and completed account and group jobs.

SSH restrictions live in `/etc/ssh/sshd_config.d/60-panasms-users.conf`. The panel validates the
effective OpenSSH configuration and reloads the service. `systemd-logind` lists and terminates SSH
sessions. Disabling an account also expires it in Linux, ends its SSH sessions and revokes managed
Samba access. Linux group changes disconnect affected SMB sessions so Samba re-evaluates access.
Removing PaNasMs keeps account state and this SSH policy, so it does not reopen access.

## Storage

The panel manages disks and mdadm RAID, partitions, filesystems, LUKS, mounts, SMART checks and
schedules, disk standby, and external NFS/SMB mounts. It does not manage LVM or a firewall. Storage
operations use server-side validation and the plan/run workflow. See
[docs/storage.md](docs/storage.md) for capabilities and recovery.

Home folders must be on a writable local Linux filesystem on permanent storage that mounts
automatically. The panel rejects USB and removable backing devices, including those beneath RAID
or encrypted volumes. These checks apply to single home creation or moves and to moving the shared
home base. Folder-selection queries list eligible roots and explain unavailable ones without
creating directories.

### Shared data volumes

PaNasMs adds local, non-service users to the `users` group. Writable local data volumes mounted
below `/srv`, `/mnt` or `/media` give that group write access at the filesystem root, and default
ACLs pass it on to new directories. Existing children keep their permissions. Files an application
creates as private stay private.

The Go `panasms-volume-access` service applies this to new mounts, including boot and on-demand
mounts. It reads the kernel mount table and local account data and does not walk files. It skips
the running system's filesystems and their aliases, system fstab targets, read-only volumes and
bind-mounted subdirectories. A data partition on the system disk is still eligible. FAT, exFAT and
NTFS use a shared group and mount masks instead of ACLs. Such volumes mounted earlier with private
masks must be detached and attached through Disks once. The service never force-unmounts a busy
volume. It cannot override permissions on remote SMB/NFS mounts.

### HDD standby

The Go system helper checks non-system SATA HDDs every 30 seconds. It measures continuous idle time
from kernel read, write, discard and flush counters and in-flight I/O, then requests standby after
the configured timeout. It disables hardware standby timers on managed disks and does not change
APM settings. Normal filesystem access wakes a disk, which can take a few seconds.

Disks backing system, boot or swap are excluded, including disks below encrypted RAID. RAID
maintenance and SMART self-tests postpone standby, and the helper only stops a disk whose SMART
status it can read. PaNasMs RAID and SMART operations share a lock with the controller. A restart,
disk replacement, configuration change or monitoring gap restarts the idle interval. Observations
live in `/run`, so monitoring never writes to data disks. The legacy storage API reaches the Go
controller through a small Python bridge.

## Shared folders

`management/sharing.py` manages local SMB and NFS publications as part of core. External SMB/NFS
mounts are a separate storage feature. The `/sharing` page has folder and connection tabs, and each
user's SMB access and password sync status is on their Security tab in Users. A folder can be
published over SMB, NFS, both or neither. Removing a publication never removes files. Legacy NFS
exports stay visible and editable.

- SMB access is enabled per Linux user. A share grants read or write access to users and groups,
  and Linux permissions remain the upper limit. Editing a folder's owner, group or mode is
  non-recursive and separate from publishing.
- A successful PAM login, own-password change or administrator reset updates the SMB password. The
  plaintext passes only through stdin in memory and is never stored in settings, jobs or logs. A
  failed sync shows on the account and in a login notification. A partial own-password failure
  still revokes sessions.
- `panasms-sharing.timer` checks Linux account state every 30 seconds (with up to five seconds of
  timer slack). Locks, expiry, UID changes and password changes made outside the panel revoke stale
  SMB access. Users without SMB access need no Samba credentials.
- NFS uses explicit client IP or subnet allowlists, numeric UID/GID and `root_squash`, without
  Kerberos, so use it only on trusted networks. Remote root does not administer a published folder.
  Per-user SMB restrictions do not apply to NFS, which uses Unix permissions.
- Shares published over both SMB and NFS disable Samba oplocks and use strict locking. Tests with
  real SMB3 and NFS4 byte-range lock conflicts cover the deployed kernel. SMB-only shares keep
  Samba's caching defaults.
- The managed files are `/etc/samba/panasms-shares.conf` and
  `/etc/exports.d/panasms-shares.exports`, and the root-only state is `/etc/panasms/sharing.json`.
  A persistent transaction journal restores the previous files and state after a failure or on
  agent startup. If someone edits a managed file by hand, the panel blocks further edits until an
  administrator restores it. The panel leaves unrelated configuration alone.
- A new installation replaces the Samba config only if it is the verified distribution default,
  and keeps the original. A customized Samba server needs manual review and the managed include.
  Guest access and automatic home or printer shares stay off. Removal stops managed publication,
  keeps user files and restores an unchanged installer-owned global config from its backup.

A published folder must already exist on a mounted local data volume. The root filesystem and
re-exports of remote mounts are rejected. Export paths with spaces or configuration metacharacters
are not supported. SMB volume UUID checks and NFS mountpoint guards stop the panel from publishing
the empty directory left when a mount disappears. Published folders block destructive operations
on their volume.

References: [smb.conf](https://www.samba.org/samba/docs/current/man-html/smb.conf.5.html),
[smbpasswd](https://www.samba.org/samba/docs/current/man-html/smbpasswd.8.html).

## Network

Network changes need confirmation within two minutes, or they roll back. Each interface keeps its
existing manager. NetworkManager uses D-Bus checkpoints. Native systemd-networkd gets a dedicated
`.network` file, and Netplan-backed Ethernet gets a dedicated YAML file instead of edits to
generated files. An independent service restores unconfirmed networkd and Netplan changes, also
after a reboot, from a durable rollback record written before the change. The editor selects
physical interfaces individually and protects Docker and other system interfaces. Configurations
it cannot represent are read-only.

NetworkManager is optional. Without it, on an active networkd system, the Go native service uses
wpa_supplicant for Wi-Fi authentication, hostapd for access points, dnsmasq for DHCP and DNS, and
policy routing with nftables for NAT on the selected uplink. Radio state is per adapter. Sharing
overlays do not rewrite wildcard interface definitions.

A packaged udev rule uses `usb-modeswitch` to switch Realtek USB Ethernet adapters that first
appear as a driver CD-ROM (`0bda:8152`) to Ethernet mode. It matches only devices with a USB
mass-storage interface and targets the exact bus and device address, so ordinary RTL8152
interfaces are untouched. The rule runs on attachment and during installation, and package
removal deletes it. The switch message comes from the
[USB_ModeSwitch device discussion](https://www.draisberghof.de/usb_modeswitch/bb/viewtopic.php?t=2972).

### Portable access

`panasms-network-access.service` is a Go controller for fallback Wi-Fi and direct USB Ethernet,
configured in Settings > Network. On a new installation with an AP-capable adapter, it enables
fallback Wi-Fi with a random SSID and password after a 90-second wait without a local Ethernet,
Wi-Fi or USB link. It does not test internet reachability, and Docker interfaces do not count. An
active fallback access point stays up while clients are connected, even after another link
returns. Saved Wi-Fi connections are kept. Stop the fallback network before choosing a saved
network by hand. Connection-sharing adapters are excluded. A manual Stop suppresses fallback until
reboot or until settings are applied again.

Save the generated Wi-Fi credentials before taking the NAS offline. They are shown in the settings,
printed by an interactive `panasms-configure`, and available to a local administrator through
`sudo /usr/lib/panasms/panasms-system-helper network-access credentials`. Keep this output
private.

USB networking works on the Pi 4/5 USB-C port, Pi Zero data ports, or a single enabled and unused
Linux USB device controller. Pi boot configuration changes need a reboot. Boards that need a
board-specific overlay are reported as unsupported and left unchanged, as are systems with several
or busy controllers. The installer owns only its marked boot block and the PaNasMs profiles. You
need a data cable and the NAS's own power supply. The link carries Ethernet, not raw storage, so
use the web panel or shared folders. Linux and macOS use the gadget network directly; Windows may
need an RNDIS driver.

USB and fallback Wi-Fi also answer captive-portal probes. Known OS connectivity-check names resolve
to a reserved `.2` address in the direct network, which redirects HTTP probes to the panel on its
current port. The redirect never accepts credentials. Other DNS queries are forwarded, and LAN,
ordinary access points, connection sharing and HTTPS are not redirected. This is legacy HTTP probe
discovery, not an RFC 8908/8910 CAPPORT API, so DHCP option 114 is not advertised. Whether the
client OS opens a "Sign in to network" prompt is up to the client, especially when another
connection already has internet access. The panel address shown in Network can always be opened by hand.
Direct-network DHCP leases start at `.20` in an unused private subnet.

The controller's root-only configuration is `/var/lib/panasms-agent/network-access/config.json`.
Transient state is in `/run`, so polling does not write to data disks. The controller respects
network rollback and package-maintenance locks, removes its listeners, alias and rules when direct
access stops, and restores them after a restart or interface recovery. Package removal stops only
its own profiles and removes its own USB configuration; boot changes take effect on reboot.

## Cooling

The `panasms-cooling` package keeps disk cooling running independently of the panel. A new
cooling configuration does not control any disk-bay GPIO. Advanced disk settings select external
power PWM (two-wire, GPIO27 by default) or built-in fan PWM (four-wire, GPIO18 at 25 kHz with a
GPIO24 tachometer). Pin numbers are BCM. Disk-bay GPIO control requires a Raspberry Pi 5 with RP1
GPIO. Mode changes check pin ownership and wait for the controller to acknowledge them, and restore
the previous configuration on failure. CPU cooling is configured separately in Settings > General
and requires writable active thermal trip points.

While all disks sleep, the controller tries to read each disk's temperature without waking it. The
first standby read of a disk is a probe: if the disk stays in standby, its temperature keeps steering
the fan as in normal operation, and the fan stops below 35 °C and starts again from 37 °C. If the read
wakes the disk, `/var/lib/panasms-cooling/sleep-reads.json` records that and the disk is not read in
standby again. As long as any sleeping disk cannot be read, the fan follows the CPU temperature
instead: off below 50 °C (on again from 52 °C), 25 % up to 60 °C, 50 % up to 65 °C, 75 % up to 70 °C
and full speed above. SMART reads do not change the block I/O counters the idle controller watches.

Capability detection is read-only and separate from the controller heartbeat. The installation
hardware report includes `supportedCooling`, and the cooling API rechecks it at runtime. A
temperature sensor alone does not enable fan controls, and a supported GPIO controller does not
prove a fan is connected. SMART and temperature polling stay configurable without fan control.

## Modules and catalog sources

Administrators manage catalog URLs from the repository icon in Modules. The official
`https://panasms.github.io/module-registry/` source is added by default. Removing a source keeps
installed modules, and with no sources the panel still accepts module archive uploads. The list is
stored in `/etc/panasms/module-sources.json`.

A custom HTTPS repository publishes `catalog.json` (schemaVersion 1 with a unique catalog id),
`catalog.sig` (an Ed25519 envelope) and `keys/<signer>.pem` (an Ed25519 public key). Choose a
unique publisher id; `panasms-*` is reserved. The catalog and module archives must be signed with
that publisher's key. The add dialog shows the key's SHA-256 fingerprint before trusting it, so
compare it with a fingerprint the publisher supplied separately. Changing the key requires explicit
reconfiguration, and the panel rejects a known publisher id with a different key.

Use the official registry as a template. Each module has `id` and `releases`, and each stable
release lists its signed `manifest`, HTTPS archive `url`, byte `size`, `sha256` and
`channel: stable`. Archives use the PaNasMs bundle format and the
[Module SDK](https://github.com/PaNasMs/module-sdk) signing procedure. Size limits, hashes,
signatures, compatibility and dependency checks are the same for every source. Downloads may
redirect over HTTPS, for example to GitHub release assets. Repository URLs cannot contain
credentials, query parameters, fragments or nonstandard ports.

Sources have priority in configured order. A duplicate module id from a later source is reported
and ignored, and an update cannot replace a module with another publisher's module. An unavailable
source reports its own error while the others keep working. Removing the last source of a custom
publisher removes its trusted key but keeps its installed modules running.

## System updates

Settings > System updates handles signed stable and testing releases, checks, downloads, automatic
installation windows and rollback. The default is the stable channel with notifications only. A
separate systemd worker with its own journal performs the update and survives package replacement.
It updates the core package and, when the release carries it, an installed `panasms-cooling`
package in the same transaction; it never installs cooling where it is absent. Cooling keeps running
during the backup, its package restarts it, and the update rolls back if cooling does not come back.
The updater does not upgrade the Linux distribution. It stops if APT would install or remove other
system packages; update those dependencies separately first. The
[update lifecycle](https://github.com/PaNasMs/panasms/blob/main/documentation/system-updates.md)
documents publication, trust, backup and recovery.

## Jobs, cancellation and recovery

Account and storage changes go through a plan, confirmation and run workflow, and each run is a
persistent job. The agent marks a job as running in its database before the helper starts. If
journal writes fail, the agent refuses new changes until database access returns and the agent is
restarted.

The job list exposes `canCancel`, `cancelRequested`, `needsReview` and an optional `recovery`
report. Queued jobs can be cancelled. Running helpers accept cancellation only at safe checkpoints,
which exist for module download and staging, home-copy preparation and Files staged copies.
Partition writes, formatting, package configuration and committed changes always run to
completion. RAID maintenance has separate pause and resume controls.

When the agent restarts, queued jobs become cancelled and running jobs become interrupted. The agent
never replays commands or credentials. The administrator inspects the actual state, runs a pending
home or module recovery or finishes package configuration, then acknowledges the result.
Inspection waits until no other task runs. Interrupted formatting or RAID changes are inspected and
never presented as reversible.

`POST /api/v1/manage?view=cancel|recover|acknowledge` takes `{ "id": "..." }`. Recovery reads
current state and does not repeat the original operation. Explicit recovery actions use the same
plan, confirmation and run workflow as other jobs.

Files publishes a copy from a sibling staging directory only after copying finishes. Cancellation
deletes the staging copy and keeps the source. An interrupted cross-filesystem move can leave both
copies and a journal, so inspect them before deleting or retrying. This is not a snapshot and
cannot undo formatting, deletion, changes to the source during the copy or power loss.

Alerts carry a severity whether or not they are active. Task notifications include the job details
and recovery context. Failures detected before any change can be recorded as needing no review.
Failed or interrupted operations with an uncertain outcome stay reviewable. Acknowledging an
operation resolves its task alert, and each user can dismiss resolved notifications. Clearing
notification or job history keeps unreviewed failures, interrupted operations and idempotency
records, and does not reset an active hardware condition.

## Native system-operation workers

The agent sends account, group, SSH, session, service, package, power and HTTP-port operations to
`panasms-system-helper` in the host mount namespace. The helper rechecks Linux identity and access,
updater state and the confirmed plan before it changes anything. `panasms-system-helper routes`
prints which operations are native and which still use Python. A native failure never falls back
to Python.

`panasms-keys` edits SSH keys and removes home contents in a separate process running with the
target user's credentials. The parent process only removes the verified, empty home directory.

Bulk home relocation (`homes.*`), storage, networking and Samba/NFS still use the Python
dispatcher. `management/account_dependencies.py` keeps Samba account status, disconnect, disable,
remove and password sync working until Samba moves to Go. It is not a fallback for account
operations.

## API contract and migrations

[api/openapi.yaml](api/openapi.yaml) documents the core query schemas, the preview and submission
protocol and the job lifecycle. `ManagementViews` maps query names to response schemas. Module
queries and action parameters belong to each module. Native smartctl and Samba fields stay open to
extension. Generate frontend types with `npm run generate:api` in the frontend checkout. The API
contract tests need `python3-yaml` and `python3-jsonschema`.

Core state and agent jobs use separate SQLite databases with WAL, `synchronous=FULL` and one
atomic transaction per migration. Append new migrations and never edit an applied one. The
checksum journal `panasms_migrations` rejects changed, missing or future schemas. The legacy core
`schema_version=1` marker remains for compatibility. A downgrade restores the matching package,
configuration and database snapshot through the updater instead of running old migrations on a
new schema.

## External connections

Google and GitHub account linking and optional panel sign-in, and Dropbox account linking, use
OAuth credentials registered for each NAS. See
[external connections](https://github.com/PaNasMs/panasms/blob/main/documentation/external-connections.md)
for the architecture, setup and Cloud Sync handoff.

## Related repositories

[PaNasMs](https://github.com/PaNasMs/panasms) ·
[Frontend](https://github.com/PaNasMs/frontend) ·
[Module SDK](https://github.com/PaNasMs/module-sdk) ·
[Module registry](https://github.com/PaNasMs/module-registry) ·
[Updates](https://github.com/PaNasMs/updates)

## License

Original code is licensed under [PolyForm Noncommercial 1.0.0](LICENSE). See [NOTICE](NOTICE) for
third-party components.
