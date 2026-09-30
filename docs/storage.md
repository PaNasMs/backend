# Storage capabilities and recovery

PaNasMs uses Linux MD, cryptsetup, filesystem and systemd tools. Disk quotas are
not implemented. Operations require administrator access and recheck the target
and its dependent layers before changing storage.

## RAID conversion

Healthy, idle MD 1.2 arrays support:

| From | To | Added disks | Result |
| --- | --- | --- | --- |
| Two-disk RAID1 | RAID5 | One empty disk | Three active members |
| RAID5 | RAID6 | One empty disk | One more active member, double parity |
| RAID6 | RAID5 | None | One fewer active member, one spare; usable capacity preserved |

New disks must be at least as large as existing members. RAID6 to RAID5 reduces
failure tolerance from two disks to one. Filesystems are not resized: use
Partitions and mounts separately. RAID0/10 conversion, arbitrary shrinking and
chunk/layout changes are not offered.

Progress and pause/resume appear on the array card. Recovery records and mdadm
backup files are kept outside the array in `/var/lib/panasms-agent/raid-reshape`.
Do not remove them during conversion. The startup service uses the saved UUID
and backup for assembly/continuation. Missing or faulty original members block
continuation; incomplete new parity in a recorded RAID5-to-RAID6 conversion is
handled separately. PaNasMs removal is blocked while recovery is still needed.

Interrupted requests are not blindly replayed. If interruption happened after
adding a spare but before starting conversion, inspect the task and array before
retrying. The presence of a spare does not authorize an arbitrary reshape.

## LUKS2 keys and recovery

The volume toolbar adds/revokes passwords, enables/disables automatic unlocking,
and backs up/restores headers. Key removal requires a password for another slot;
the last key cannot be removed. Disable automatic unlocking before removing its
managed key.

Automatic unlocking stores a private key in `/etc/panasms/luks` and a managed
`/etc/crypttab` entry. `systemd-cryptsetup` is an installation dependency. The
policy takes effect on next startup; disabling it keeps an open mapping available.
A key on the NAS does not protect against theft of the whole NAS. Keep a working
password and an independent header backup. Uninstall retains keys and crypttab
entries so data stays accessible.

Backups are `<UUID>.luks-header`, mode 0600, in the selected folder. Existing files
are not overwritten. Restore requires a closed, unused container and matching
UUID. It restores old keys, including revoked keys, but not file contents. The
panel needs a readable current LUKS identity; a completely destroyed header
requires an offline cryptsetup recovery workflow.

## Mount policies

- Manual: remember the location without mounting at startup.
- At startup: mount through fstab/systemd with a bounded device wait.
- On access: systemd automount with a ten-minute idle timeout.

Policy edits apply at next startup and do not unmount an active volume. Unmount
refuses dependent mounts, exports, open processes and user homes with an
explanation of the blocker.

## Btrfs snapshots

Mounted writable Btrfs volumes offer read-only snapshots in a private
`.panasms-snapshots` directory. Restore creates a writable copy in a new folder,
without overwriting current files. Nested subvolumes are excluded. Deleting a
snapshot preserves the live tree. Snapshots on the same disk are not backups.
Other filesystems do not offer snapshot actions.

## Monitoring and validation

SMART schedules show their next slot in NAS time; a busy array or running test
can defer the actual run. History retains seven days with one sample per minute,
point inspection, min/mean/max and a measurement table.

Root-only integration scripts create their own loop images on a live Linux host.
Coverage includes LUKS keys/header roundtrips, systemd unlock/automount units,
Btrfs snapshots, RAID conversion/pause/resume/reassembly, degraded replacement,
ENOSPC and read-only filesystems. These do not certify every physical power-loss
or controller failure. Hardware standby and cooling need target-device acceptance.
