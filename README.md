# PaNasMs backend

The Linux server for **Pavlo's NAS Management System**. The current 0.2.x
prototype combines a Go HTTP/WebSocket core, a privileged Go agent and Python
system-management adapters. The deployed target is Raspberry Pi OS ARM64.

[Project website](https://panasms.github.io/) ·
[System update lifecycle](https://github.com/PaNasMs/panasms/blob/main/documentation/system-updates.md)

## Architecture

- **Core** serves the SPA, HTTP API, sessions, user preferences, wallpaper,
  notifications and metrics. It runs as the restricted `panasms` service user.
- **Agent** authenticates through PAM and executes authorized system operations
  through a local Unix socket. It stores persistent jobs separately from core.
- **System adapters** integrate Linux tools and services; Linux remains the source
  of truth for users, disks, mounts, RAID and network configuration.
- **Installable modules** run as separate services. Files, Terminal and Cloud Sync
  have their own repositories and signed packages; their code is not installed
  as part of the core package.
- **Cooling** has an independent package and service, so removing the panel does
  not stop the disk cooling controller.

The implementation uses `net/http`, chi, coder/websocket, `database/sql` with
SQLite, PAM through cgo, and systemd. SQLite schema initialization and migrations
live in the Go store packages; there is no sqlc generation step.

## Implemented system areas

Linux users/groups, profiles and SSH keys; home relocation; disks and mdadm RAID;
partitions, filesystems, LUKS and mounts; SMART checks and schedules; disk standby;
CPU/disk cooling; local SMB/NFS shared folders and external NFS/SMB mounts; NetworkManager Ethernet/Wi-Fi, access
points and connection sharing; system services, journal, updates and power
operations; module installation and the signed online catalog.

Network changes use confirmation and rollback. Storage and account operations
use server-side validation and the management plan/run workflow. UI visibility
is not an authorization boundary. Dedicated firewall and LVM management remain
outside the current interface.

Realtek USB Ethernet adapters that initially expose a driver CD-ROM as
`0bda:8152` are switched to Ethernet mode by a packaged udev rule using
`usb-modeswitch`. The rule requires a USB mass-storage interface and targets the
exact USB bus/device address; ordinary RTL8152 network interfaces are left alone.
It runs on attachment and is also applied to matching devices during installation.
Removing the package removes the rule. The switch message is documented in the
[USB_ModeSwitch device discussion](https://www.draisberghof.de/usb_modeswitch/bb/viewtopic.php?t=2972).

Home-folder destinations must use a writable local Linux filesystem on permanent
storage, mounted automatically. USB and removable backing devices are rejected,
including members beneath RAID or encrypted volumes. The checks run for individual
home creation/moves and moving the shared home base. Read-only folder-selection
queries expose eligible roots and explain unavailable locations; they do not
create directories or replace the validation performed by each operation.

## Task cancellation and recovery

The job list exposes `canCancel`, `cancelRequested`, `needsReview` and an optional
`recovery` report. Cancellation is cooperative: queued work can be cancelled;
running helpers accept a request only at safe checkpoints. Module download and
staging, home-copy preparation, and Files 0.2.12 staged copies support this.
Partition writes, formatting, package configuration and committed changes are
not terminated midway. RAID maintenance has separate pause/resume controls.

After agent restart, queued jobs become cancelled and running jobs become
interrupted. Commands and credentials are never replayed automatically. The
administrator can inspect actual domain state, run a pending home/module
recovery or finish incomplete package configuration, then acknowledge the result.
Clearing history retains unreviewed failures and interrupted operations, and
preserves idempotency records. Inspection is blocked while other tasks run.

Files copies are published from a sibling staging directory only after copying
finishes. Cancellation removes that staging copy and preserves the source.
Interrupted cross-filesystem moves can retain both copies and a journal; inspect
them before deleting or retrying. This is not a filesystem snapshot or an undo
mechanism for formatting, deletion, live source modifications or power loss.
Destructive-operation recovery still requires domain-specific checks and backups.

`POST /api/v1/manage?view=cancel|recover|acknowledge` accepts `{ "id": "..." }`.
Recovery reads current state; it does not repeat the original operation. Explicit
recovery actions use the same fresh plan/confirmation/run workflow as other jobs.

## Source map

| Path | Contents |
| --- | --- |
| [cmd](cmd) | Core and agent entry points |
| [internal](internal) | API, identity, persistence, jobs, metrics and module integration |
| [management](management) | Python Linux adapters and module installation/catalog logic |
| [api/openapi.yaml](api/openapi.yaml) | OpenAPI contract; management operations are not fully described yet |
| [api/events.md](api/events.md) | Event WebSocket protocol |
| [packaging](packaging) | Debian hooks, systemd units, PAM policy and administration tools |
| [cooling](cooling) | Independent disk cooling controller |
| [scripts](scripts) | Build and installation migration tools |
| [tests](tests) | Python adapter tests; Go tests live beside their packages |

## Build and test

Use Linux, Go 1.26 or newer, Python 3, a C compiler and PAM development headers
(`libpam0g-dev` on Debian). CGO is required for PAM and SQLite.

The Python test suite also contains Files-module regression checks. Clone
[module-files](https://github.com/PaNasMs/module-files) at `../modules/files`
in the workspace layout and install Pillow (`python3-pil` on Debian) before
running `make check`. The CI workflow prepares these test dependencies explicitly.

```sh
make check
make check-race
make build
```

`make check` runs Go tests with PAM, Go vet and Python unit tests. `make build`
produces `bin/panasms-core` and `bin/panasms-agent`.

Build the [frontend](https://github.com/PaNasMs/frontend) first, then package its
static output on the target architecture:

```sh
sh scripts/build-deb.sh ../frontend/dist
sh scripts/build-cooling-deb.sh
```

Outputs are `dist/panasms-prototype_0.2.5_<architecture>.deb` and
`dist/panasms-cooling_0.2.0_all.deb`. The package script expects a native Go build;
ARM64 is the tested deployment target. Go binaries can be built without frontend
sources, but the prototype Debian package requires prebuilt SPA assets.

The core package version defaults to [VERSION](VERSION). CI supplies a unique
prerelease through `PANASMS_PACKAGE_VERSION`; `PANASMS_COOLING_VERSION` similarly
overrides the optional cooling package version. Both are validated by `dpkg`.
See the [automated build guide](https://github.com/PaNasMs/panasms/blob/main/documentation/builds.md)
for native ARM64/AMD64 artifacts, source manifests and validation limits.

## Users, groups and personal access

The Users section reads local Linux users and groups on every request. Membership
in `sudo` (primary or supplementary) grants administration. Root, service UIDs,
non-local and ambiguous duplicate-UID accounts are visible but protected.
Ordinary accounts require explicit panel access in `/etc/panasms/accounts.json`;
existing sudo users retain bootstrap access. The optional deployment allowlist
remains an additional restriction.

Administrators manage account names, primary/supplementary groups, homes, UID,
expiry, password aging, forced password changes, SSH keys and panel/SSH sessions.
New accounts have a private home and panel access; SSH is disabled by default.
Deletion defaults to removing only the home; shared-folder files are preserved.
Busy homes return named process/service blockers. Self-lockout and removal of the
last available administrator are blocked. UID changes update home ownership via
`usermod`; ownership on other volumes requires a separate administrator decision.

Passwords follow the host PAM configuration, without an extra application strength
policy. Own-password changes use the `passwd` PAM stack with the caller's real UID
and effective root identity, as the system password utility does. Administrator
resets use `chpasswd`. Expired passwords must be changed before a session is issued.
Panel sessions are rechecked against live Linux access, UID and revocation epoch;
password resets and access/membership changes revoke affected sessions.

Ordinary users access their profile, avatar, language, desktop preferences, read-only
system widgets and Files under their own Linux permissions. They cannot administer
storage, network, modules, users, service settings or other users' sessions/tasks.
Terminal and Cloud Sync remain administrator-only. Security history records panel
sign-ins, profile changes, session termination and completed account/group jobs.
SSH sessions are discovered and terminated through `systemd-logind`.

SSH restrictions use `/etc/ssh/sshd_config.d/60-panasms-users.conf`, validate effective
OpenSSH configuration and reload the service. Disabling an account also expires it
in Linux and terminates SSH sessions. Managed Samba access is also revoked; Linux group changes disconnect affected
SMB sessions so access is evaluated again. Removing PaNasMs preserves Linux account state
and this SSH policy rather than silently reopening access.

## Installation and operation

On the target Debian-based machine, run `sudo apt update`, then install the generated
prototype package with `sudo apt install ./<package>.deb` so OS dependencies are
resolved, then run
`sudo panasms-configure` (HTTP port 80 on a fresh installation). Use
`sudo panasms-configure --port 8080` to choose a different port. Running without
`--port` preserves an existing choice. It requires an existing non-root user in the Linux
`sudo` group; it does not create an administrator. Review hardware support before
installing/configuring the optional cooling package.

The package declares required runtime tools in Debian `Depends`, including mdadm
and initramfs-tools for RAID, partition/filesystem and SMART utilities,
NetworkManager and wpasupplicant for Ethernet/Wi-Fi, Samba/NFS tools, and PAM/session
support. They are installed even with `--no-install-recommends`; access to the
configured distribution repositories is required. `dpkg -i` alone does not download
dependencies. CI resolves the complete dependency tree using an empty installed-package
status database on both architectures. SSH server support remains optional and is
available when OpenSSH server is installed; hardware-specific cooling is a separate package.

Administrators can also change the HTTP port in Settings → General, alongside CPU
cooling. Occupied and browser-blocked ports are rejected. The panel restarts; the browser checks the new address and redirects automatically when it responds.
A manual link remains available if the browser cannot verify it. Failed startup restores the previous port. The choice
is stored in `/etc/panasms/web.env` and survives package upgrades. The source
installer accepts `--port PORT` too.

The packaged prototype serves HTTP on port 80 by default. The core binary also accepts TLS
certificate/key flags. Runtime configuration is in `/etc/panasms/panasms.env`;
core state is in `/var/lib/panasms`, and agent jobs/state in `/var/lib/panasms-agent`.
Inspect `panasms-core`, `panasms-agent` and, if installed, `panasms-cooling` with
`systemctl` and `journalctl`.

`sudo panasms-uninstall --plan` previews removal. `--remove` removes the panel;
`--purge` additionally removes panel-owned state. User data, Linux accounts,
RAID and mounts are retained. The separate cooling package is retained.
Review the plan before using either removal mode.

The one-time `scripts/migrate-ostojaos.py` helper applies only to its explicitly
validated legacy installation and supplied backup artifacts. It is not a general
installer or a substitute for future upgrade migrations.

## Related repositories and license

[Workspace](https://github.com/PaNasMs/panasms) ·
[Frontend](https://github.com/PaNasMs/frontend) ·
[Module SDK](https://github.com/PaNasMs/module-sdk) ·
[Registry](https://github.com/PaNasMs/module-registry)

Internal planning/deployment documents are not public. Public documentation is
maintained in English. Original code: [PolyForm Noncommercial 1.0.0](LICENSE);
third-party scope: [NOTICE](NOTICE).

## Shared folders (system module)

`management/sharing.py` owns local publications; it is part of core, not an
installable package. External SMB/NFS mounts remain a separate storage feature.
The `/sharing` page offers folder and connection tabs. SMB access and password
synchronization status belong to each user’s Security tab in Users. A folder can
be published through SMB, NFS, both, or neither; removing a publication never
removes files. Existing legacy NFS exports remain visible and editable.

- SMB access is explicitly enabled per Linux user. Shares select users/groups
  for read or write access; Linux permissions remain the upper bound. Folder
  owner/group/mode editing is nonrecursive and separate from publication.
- Successful PAM password login, own-password change and administrator reset
  synchronize the SMB password. Plaintext only crosses stdin in memory; it is
  never stored in settings/jobs/logs. A sync failure has a visible account status
  and login notification; a partial own-password failure still revokes sessions.
- `panasms-sharing.timer` checks Linux account state every 30 seconds (up to five
  seconds timer slack). External locks, expiry, UID changes and password changes
  revoke stale SMB access. A successful panel password login provisions the new
  password. SMB-disabled users need no Samba credentials.
- NFS uses explicit client IP/subnet allowlists, numeric UID/GID and root_squash.
  It is intended for trusted networks, without Kerberos. Remote root is not an
  administrator of a published folder. Per-user SMB restrictions do not replace
  NFS's underlying Unix permissions.
- Joint SMB/NFS shares disable Samba oplocks and use strict locking; real SMB3
  and NFS4 byte-range lock conflict tests cover the deployed Linux kernel.
  SMB-only shares keep normal Samba caching defaults.
- Managed fragments are `/etc/samba/panasms-shares.conf` and
  `/etc/exports.d/panasms-shares.exports`; state is root-only
  `/etc/panasms/sharing.json`. A persisted transaction journal restores prior
  fragments/state on failure or agent startup. External fragment edits block
  further edits until explicitly restored. Changes to unrelated administrator
  configuration are not overwritten.
- New installation replaces only the verified distribution-default Samba config,
  saving its original. A customized existing Samba server requires manual review
  and the managed include. Guest access and automatic home/printer publication
  are not enabled. Removal stops managed publication and preserves user files;
  an unchanged installer-owned global config is restored from its backup.

Publication currently requires an existing folder on a mounted local data volume;
root filesystem and remote-mount re-export are rejected. Spaces/configuration
metacharacters in export paths are not supported. Create folders using Files
before publishing them. SMB volume UUID checks and NFS mountpoint guards prevent
publishing a fallback directory when a backing mount disappears. NFS and SMB
publications also block destructive volume operations in the storage manager.

References: [Samba configuration](https://www.samba.org/samba/docs/current/man-html/smb.conf.5.html)
and [smbpasswd](https://www.samba.org/samba/docs/current/man-html/smbpasswd.8.html).

## Additional module repositories

Administrators can manage catalog URLs from the repository icon in Modules.
The official `https://panasms.github.io/module-registry/` source is added by default.
Removing a source keeps installed modules; an empty list permits file installation.
Configuration is stored in `/etc/panasms/module-sources.json`.

A custom HTTPS repository publishes `catalog.json` (schemaVersion 1 with a unique
catalog id), `catalog.sig` (Ed25519 envelope), and `keys/<signer>.pem` (Ed25519
public key). Use a unique publisher id; `panasms-*` is reserved. Its catalog and
module archives must use that publisher's key. The add dialog displays the key's
SHA-256 fingerprint before granting trust. Compare it with the publisher's
independently supplied fingerprint. A key change requires explicit reconfiguration;
a reused publisher id with a different key is rejected.

Use the official registry schema as a template: each module has `id` and `releases`;
each stable release provides its signed `manifest`, HTTPS archive `url`, byte `size`,
`sha256`, and `channel: stable`. The archive uses the existing PaNasMs bundle format
and SDK signing procedure. Archive size limits, hashes, signatures, compatibility
and dependency checks apply equally to every source. Downloads may redirect over
HTTPS (including GitHub release assets). Repository URLs do not accept credentials,
query parameters, fragments or nonstandard ports.

Sources have deterministic priority in configured order; a duplicate module id
from a later source is reported and ignored. Updates cannot silently replace an
installed module with another publisher's module. An unavailable source reports
its own error while healthy sources remain visible. Removing the last source for
a custom publisher removes its trusted key; running installed modules are retained.

## System updates

Settings → System updates controls signed stable/testing releases, checks, downloads,
automatic installation windows and rollback. The independent systemd worker retains
its own journal and code across package replacement. It updates the core package,
leaving Linux distribution upgrades and hardware cooling separate. The default is
stable with notifications only. See the [update lifecycle](https://github.com/PaNasMs/panasms/blob/main/documentation/system-updates.md)
for publication, trust, backup and recovery guarantees and limitations.

## Actionable notifications

Alert responses include a severity classification independently of whether the
alert is active. Task notifications expose the original job details and recovery
context. Known failures before mutation can be recorded as requiring no review;
failed or interrupted operations with uncertain outcomes remain reviewable.
Acknowledging an operation resolves its task alert, and resolved notifications
can be dismissed per user. Clearing notification history does not acknowledge
unreviewed work or reset an active hardware condition.

## Core contracts, migrations and interruption safety

The [management API contract](api/openapi.yaml) documents the core query schemas,
preview/submission protocol and persistent task lifecycle. `ManagementViews` maps
query names to response schemas; module queries and action parameters belong to
the owning module. Native smartctl and Samba fields remain extensible. Generate
frontend types with `npm run generate:api` in the adjacent frontend checkout.

Core state and agent jobs use separate SQLite databases with WAL, FULL synchronous
writes and one atomic migration transaction. Append migrations; never edit an
applied migration. The checksum journal rejects changed, gapped or future schemas.
The legacy core `schema_version=1` marker is retained for compatibility; the
`panasms_migrations` journal is authoritative. Downgrades restore the matching
package/configuration/database snapshot through the updater instead of rewriting
new schemas with old migrations.

A job must be durably marked running before its helper starts. If journal writes
fail, new mutations are suspended until database access is restored and the agent
is restarted. Running helpers reach their own safe completion points. On restart,
queued jobs are cancelled and running jobs become interrupted, requiring inspection;
operation credentials and commands are never replayed. Interrupted formatting or
RAID changes are inspected, not advertised as automatically reversible.

The regression suite includes legacy adoption, failed/future migrations, process
crashes inside migration and job execution, journal write failures, cooperative
cancellation, conflicting work ordering and independent work concurrency. API
contract tests require `python3-yaml` and `python3-jsonschema` in addition to the
existing native/Python test dependencies. Run `make check` and `make check-race`.
These tests use temporary data; physical power-loss and hardware-controller behavior
remain separate installation acceptance checks.

## Native system-operation workers

The agent routes account/group/SSH/session operations, services, system packages,
power operations and HTTP-port changes to `panasms-system-helper` in the host mount
namespace. The helper rechecks Linux identity and access, updater state and the
confirmed plan before crossing the mutation boundary. Interrupted operations are
inspected, never automatically replayed. `panasms-system-helper routes` prints the
complete native/legacy inventory; a native failure never falls back to Python.

`panasms-keys` performs SSH-key edits and home-content removal in a separate process
with the target user's credentials. The parent only removes the verified, empty
home directory. Host PAM/password rules remain authoritative.

Other domains still use the explicit legacy dispatcher. In particular, bulk home
relocation (`homes.*`), storage, networking and Samba/NFS have not been migrated.
The narrow `management/account_dependencies.py` bridge preserves Samba account
status, disconnect/disable/remove and password synchronization until that domain
moves to Go. This is not a fallback for an account operation.

`make check-accounts-integration` builds the workers and runs disposable account
and PAM tests in user/mount/PID/network namespaces. It needs Linux user namespaces,
`newuidmap`/`newgidmap` with subordinate UID/GID ranges, PAM development headers and
standard account tools. Host accounts are never modified. Account commands, PAM,
keys and home moves/deletion are real; systemd and storage discovery use fixtures.
The tests compare native queries, plans and recovery reports with the legacy
contract. Live hardware and service-manager deployment remain separate checks.

## External connections

Google account linking and optional panel sign-in use NAS-specific OAuth credentials. See the [architecture, setup and Cloud Sync handoff](https://github.com/PaNasMs/panasms/blob/main/documentation/external-connections.md).
