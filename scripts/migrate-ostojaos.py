#!/usr/bin/env python3
"""Migrate the local OstojaOS prototype installation to PaNasMs 0.2.1."""
import argparse
import grp
import hashlib
import http.client
import json
import os
from pathlib import Path
import pwd
import shutil
import socket
import sqlite3
import subprocess
import sys
import tarfile
import time
import urllib.request
import uuid

MODULES = {"files": "0.2.11", "terminal": "0.2.3", "cloud-sync": "0.1.5"}

STATE = [
    "/etc/ostojaos",
    "/etc/ostojaos-cooling",
    "/var/lib/ostojaos",
    "/var/lib/ostojaos-agent",
    "/var/lib/ostojaos-installer",
    "/var/lib/ostojaos-modules",
    "/var/lib/ostojaos-cloud-sync",
]


def run(*args, check=True):
    return subprocess.run(args, check=check, text=True, capture_output=True)


def disable_cleanup(prefix, backup, info=Path('/var/lib/dpkg/info')):
    path = info / (prefix + '-prototype.prerm')
    if path.exists():
        shutil.copy2(path, backup / (prefix + '-prototype.prerm'))
        # Removal hooks tear down Wi-Fi and sharing; a namespace migration retains them.
        path.write_text('#!/bin/sh\nexit 0\n')


def units(prefix):
    data = json.loads(
        run("systemctl", "list-unit-files", prefix + "-*", "--output=json", "--no-pager").stdout
    )
    return [r["unit_file"] for r in data], [r["unit_file"] for r in data if r["state"] == "enabled"]


def move(source, destination):
    source, destination = Path(source), Path(destination)
    if not source.exists():
        return
    if source.is_symlink() or destination.exists() or destination.is_symlink():
        raise RuntimeError("Unsafe or occupied migration path: " + str(source))
    destination.parent.mkdir(parents=True, exist_ok=True)
    source.rename(destination)


def user_state(path):
    with sqlite3.connect("file:" + str(path) + "?mode=ro", uri=True) as db:
        return {
            "preferences": db.execute("select username,value from preferences order by username").fetchall(),
            "wallpapers": [
                (u, v, hashlib.sha256(image).hexdigest())
                for u, v, image in db.execute(
                    "select username,version,image from wallpapers order by username"
                )
            ],
        }


def mounts():
    return json.loads(run("findmnt", "--json", "--list", "--real", "-o", "TARGET,SOURCE,FSTYPE").stdout)[
        "filesystems"
    ]


def preflight(artifacts):
    if os.geteuid() != 0:
        raise RuntimeError("Run as root")
    if run("dpkg", "--print-architecture").stdout.strip() != "arm64":
        raise RuntimeError("This migration requires ARM64 packages")
    for filename in [
        "backend/dist/panasms-prototype_0.2.1_arm64.deb",
        "backend/dist/panasms-cooling_0.2.0_all.deb",
        "files-0.2.11-arm64.panasms",
        "terminal-0.2.3-arm64.panasms",
        "cloud-sync-0.1.5-arm64.panasms",
        "rollback/ostojaos-prototype_0.2.1_arm64.deb",
        "rollback/ostojaos-cooling_0.2.0_all.deb",
    ]:
        if not (artifacts / filename).is_file():
            raise RuntimeError("Missing artifact: " + filename)
    sys.path.insert(0, str(artifacts / "backend/management"))
    import module_manager as manager

    original_keys = manager.KEYS
    manager.KEYS = artifacts / "backend/packaging"
    try:
        for mid, version in MODULES.items():
            _, manifests = manager.inspect_bundle(artifacts / (mid + "-" + version + "-arm64.panasms"))
            missing, _ = manager.package_plan(list(manifests.values()))
            if missing:
                raise RuntimeError("Install module prerequisites before migration: " + ", ".join(missing))
    finally:
        manager.KEYS = original_keys
    for name in STATE + ["/usr/lib/ostojaos", "/usr/lib/ostojaos-cooling"]:
        new = Path(name.replace("ostojaos", "panasms"))
        if new.exists() or new.is_symlink():
            raise RuntimeError("PaNasMs destination already exists: " + str(new))
    try:
        pwd.getpwnam("panasms")
    except KeyError:
        pass
    else:
        raise RuntimeError("PaNasMs account already exists")
    account = pwd.getpwnam("ostojaos")
    if account.pw_gecos != "OstojaOS prototype service" or account.pw_shell != "/usr/sbin/nologin":
        raise RuntimeError("Unexpected OstojaOS service account")
    if grp.getgrnam("ostojaos").gr_gid != account.pw_gid:
        raise RuntimeError("Unexpected OstojaOS service group")
    if not Path("/var/lib/ostojaos-installer/created-user").is_file():
        raise RuntimeError("OstojaOS service account ownership marker is missing")
    for package, version in [("ostojaos-prototype", "0.2.1"), ("ostojaos-cooling", "0.2.0")]:
        if run("dpkg-query", "-W", "-f=${Version}", package).stdout != version:
            raise RuntimeError("Unexpected installed package version: " + package)
    with sqlite3.connect("file:/var/lib/ostojaos-agent/jobs.db?mode=ro", uri=True) as db:
        if db.execute("select count(*) from jobs where status in ('queued','running')").fetchone()[0]:
            raise RuntimeError("Wait for active panel jobs before migration")
    for path in Path('/var/lib/ostojaos-agent').glob('network*/pending.json'):
        if json.loads(path.read_text()).get('status') in ('applying', 'pending'):
            raise RuntimeError('Confirm or roll back the pending network change first')
    groups = Path('/var/lib/ostojaos-agent/network-sharing/groups.json')
    if groups.exists() and json.loads(groups.read_text()):
        raise RuntimeError('This migration requires network sharing to be stopped and removed first')
    if list(Path('/etc/NetworkManager/conf.d').glob('*ostojaos*')):
        raise RuntimeError('Review per-adapter Wi-Fi overrides before migration')
    for path in Path('/etc/systemd/system').glob('ostojaos-*'):
        if path.is_dir():
            raise RuntimeError('Review custom systemd override directory: ' + str(path))
    for path in Path('/var/lib/ostojaos-cloud-sync').glob('*/state.db'):
        with sqlite3.connect('file:' + str(path) + '?mode=ro', uri=True) as db:
            if db.execute('select count(*) from tasks').fetchone()[0]:
                raise RuntimeError('Cloud Sync task migration needs a separate data-path review')
    registry = json.loads(Path("/var/lib/ostojaos-modules/registry.json").read_text())
    if set(registry) != set(MODULES):
        raise RuntimeError("Unexpected installed modules; update the migration plan")
    for mid, manifest in registry.items():
        if not manifest.get("enabled"):
            continue
        conn = http.client.HTTPConnection("localhost", timeout=3)
        conn.sock = socket.socket(socket.AF_UNIX)
        conn.sock.settimeout(3)
        try:
            conn.sock.connect("/run/ostojaos-modules/" + mid + ".sock")
            conn.request("GET", "/health")
            if json.loads(conn.getresponse().read())["active"]:
                raise RuntimeError("Close active module sessions/transfers: " + mid)
        finally:
            conn.close()
    for md in Path("/sys/class/block").glob("md*/md/sync_action"):
        if md.read_text().strip() not in ("idle", "frozen"):
            raise RuntimeError("Wait for RAID maintenance to finish")
    return registry


def restore(backup):
    meta = json.loads((backup / "migration.json").read_text())
    new_units, _ = units("panasms")
    if new_units:
        run("systemctl", "disable", "--now", *new_units, check=False)
    cooling = Path("/etc/panasms-cooling")
    if cooling.exists():
        move(cooling, backup / "failed/etc/panasms-cooling")
    disable_cleanup("panasms", backup)
    run("dpkg", "--remove", "panasms-prototype", "panasms-cooling", check=False)
    for name in STATE:
        new = name.replace("ostojaos", "panasms")
        if Path(new).exists():
            move(new, backup / "failed" / new.lstrip("/"))
    for name in ["/usr/lib/panasms", "/usr/lib/panasms-cooling"]:
        if Path(name).exists():
            move(name, backup / "failed" / name.lstrip("/"))
    for old, new in reversed(meta.get("trash_moves", [])):
        if Path(new).exists() and not Path(old).exists():
            move(new, old)
    try:
        pwd.getpwnam("panasms")
    except KeyError:
        pass
    else:
        run("usermod", "-l", "ostojaos", "-c", "OstojaOS prototype service", "panasms")
        if any(g.gr_name == "panasms" for g in grp.getgrall()):
            run("groupmod", "-n", "ostojaos", "panasms")
    run("tar", "--acls", "--xattrs", "-xpf", str(backup / "state.tar"), "-C", "/")
    for unit in Path("/etc/systemd/system").glob("panasms-*"):
        if unit.is_file() or unit.is_symlink():
            unit.unlink()
    artifacts = Path(meta["artifacts"])
    run(
        "dpkg",
        "-i",
        str(artifacts / "rollback/ostojaos-prototype_0.2.1_arm64.deb"),
        str(artifacts / "rollback/ostojaos-cooling_0.2.0_all.deb"),
    )
    run("hostnamectl", "set-hostname", meta["hostname"])
    run("systemctl", "daemon-reload")
    run("udevadm", "control", "--reload-rules")
    run("systemctl", "enable", "--now", *meta["enabled"])
    print("Previous installation restored. Backup:", backup, flush=True)


def migrate(artifacts):
    registry = preflight(artifacts)
    old_units, enabled = units("ostojaos")
    backup = Path("/var/backups/panasms-migration") / time.strftime("%Y%m%d-%H%M%S")
    backup.mkdir(parents=True, mode=0o700)
    backup.chmod(0o700)
    meta = {
        "artifacts": str(artifacts),
        "enabled": enabled,
        "hostname": run("hostname").stdout.strip(),
        "trash_moves": [],
    }

    def save():
        (backup / "migration.json").write_text(json.dumps(meta, indent=2))

    save()
    before = user_state("/var/lib/ostojaos/state.db")
    before_mounts = mounts()
    # Preserve each original file byte-for-byte, including credential files and SQLite WALs.
    snapshot = STATE + ["/etc/fstab", "/etc/hostname", "/etc/hosts", "/etc/pam.d/ostojaos", "/etc/NetworkManager/conf.d"]
    snapshot += [str(p) for p in Path("/etc/systemd/system").glob("ostojaos-*")]
    try:
        run("systemctl", "stop", "ostojaos-core.service")
        preflight(artifacts)
        run("systemctl", "stop", "ostojaos-fs-check@*.service")
        run("systemctl", "stop", "ostojaos-cloud-sync-user-*.service")
        run("systemctl", "stop", *[u for u in old_units if u != "ostojaos-cooling.service" and "@." not in u])
        snapshot = [p.lstrip("/") for p in snapshot if Path(p).exists()]
        run("tar", "--acls", "--xattrs", "-cpf", str(backup / "state.tar"), "-C", "/", *snapshot)
    except Exception:
        run("systemctl", "start", *enabled)
        raise
    print("Backup created:", backup, flush=True)
    try:
        run("systemctl", "disable", *enabled)
        run("systemctl", "stop", "ostojaos-cooling.service")
        for name in STATE:
            move(name, name.replace("ostojaos", "panasms"))
        disable_cleanup("ostojaos", backup)
        run("dpkg", "--remove", "ostojaos-prototype", "ostojaos-cooling")
        for name in ["/usr/lib/ostojaos", "/usr/lib/ostojaos-cooling"]:
            if Path(name).exists():
                move(name, backup / "retired" / name.lstrip("/"))
        run("usermod", "-l", "panasms", "-c", "PaNasMs prototype service", "ostojaos")
        run("groupmod", "-n", "panasms", "ostojaos")
        env = Path("/etc/panasms/ostojaos.env")
        lines = env.read_text().splitlines(keepends=True)
        env.write_text(
            "".join(
                "PANASMS_" + line[len("OSTOJAOS_") :] if line.startswith("OSTOJAOS_") else line for line in lines
            )
        )
        env.rename(env.with_name("panasms.env"))
        for signer in ('local', 'ci'):
            move('/etc/panasms/module-keys/ostojaos-' + signer + '.pem',
                 '/etc/panasms/module-keys/panasms-' + signer + '.pem')
        for name in ('/etc/pam.d/ostojaos',):
            if Path(name).exists():
                move(name, backup / 'retired' / name.lstrip('/'))
        fstab = Path("/etc/fstab")
        fstab.write_text(
            fstab.read_text()
            .replace("/etc/ostojaos/network-credentials/", "/etc/panasms/network-credentials/")
            .replace("# ostojaos-network-", "# panasms-network-")
        )
        for unit in Path("/etc/systemd/system").glob("ostojaos-*"):
            if unit.is_file() and not unit.is_symlink():
                target = unit.with_name(unit.name.replace("ostojaos-", "panasms-", 1))
                target.write_text(
                    unit.read_text()
                    .replace("ostojaos", "panasms")
                    .replace("OSTOJAOS", "PANASMS")
                    .replace("OstojaOS", "PaNasMs")
                    .replace("PiNAS", "PaNasMs")
                )
                target.chmod(0o644)
            unit.unlink()
        # Signed payloads must be reinstalled, never edited in place.
        for mid in registry:
            move("/var/lib/panasms-modules/" + mid, backup / "retired-modules" / mid)
        Path("/var/lib/panasms-modules/registry.json").write_text("{}")
        Path("/var/lib/panasms-modules/catalog.json").write_text("{}")
        run(
            "dpkg",
            "-i",
            str(artifacts / "backend/dist/panasms-cooling_0.2.0_all.deb"),
            str(artifacts / "backend/dist/panasms-prototype_0.2.1_arm64.deb"),
        )
        run("systemctl", "enable", "--now", "panasms-cooling.service")
        sys.path.insert(0, "/usr/lib/panasms/management")
        import module_manager as manager

        manager.UPLOADS.mkdir(mode=0o700, parents=True, exist_ok=True)
        for mid, manifest in registry.items():
            token = uuid.uuid4().hex
            upload = manager.UPLOADS / ("pasha-" + token + ".zip")
            shutil.copyfile(artifacts / (mid + "-" + MODULES[mid] + "-arm64.panasms"), upload)
            upload.chmod(0o600)
            manager.execute("module.install", {"upload": token}, "pasha")
            if not manifest["enabled"]:
                manager.execute("module.disable", {"target": mid}, "pasha")
        roots = {Path("/"), *(Path(u.pw_dir) for u in pwd.getpwall() if u.pw_uid >= 1000 and u.pw_dir.startswith("/"))}
        roots.update(
            Path(m["target"]) for m in before_mounts if m["target"].startswith(("/srv/", "/mnt/", "/media/"))
        )
        for root in roots:
            if not root.is_dir() or root.is_symlink():
                continue
            for old in root.glob(".ostojaos-trash-*"):
                if old.is_symlink() or not old.is_dir() or not old.name[len(".ostojaos-trash-") :].isdigit():
                    continue
                new = old.with_name(old.name.replace(".ostojaos-trash-", ".panasms-trash-", 1))
                meta["trash_moves"].append((str(old), str(new)))
                save()
                move(old, new)
        timers = [u.replace("ostojaos-", "panasms-", 1) for u in enabled if u.endswith(".timer")]
        if timers:
            run("systemctl", "enable", "--now", *timers)
        run("panasms-configure")
        for attempt in range(30):
            try:
                health = json.load(urllib.request.urlopen("http://127.0.0.1/api/v1/health", timeout=2))
                if health["status"] == "ok" and health["version"] == "0.2.1":
                    break
            except (OSError, ValueError):
                pass
            time.sleep(1)
        else:
            raise RuntimeError("New core failed health check")
        if before != user_state("/var/lib/panasms/state.db"):
            raise RuntimeError("Preferences or wallpaper changed during migration")
        after = mounts()
        for row in before_mounts:
            if row["target"].startswith(("/srv/", "/mnt/", "/media/")) and row not in after:
                raise RuntimeError("Existing data mount changed: " + row["target"])
        run("systemctl", "is-active", "panasms-core", "panasms-agent", "panasms-cooling")
        if meta["hostname"] == "ostojaos":
            hosts = Path("/etc/hosts")
            hosts.write_text(
                "\n".join(
                    (
                        " ".join("panasms" if part == "ostojaos" else part for part in line.split())
                        if line.startswith("127.0.1.1")
                        else line
                    )
                    for line in hosts.read_text().splitlines()
                )
                + "\n"
            )
            run("hostnamectl", "set-hostname", "panasms")
        meta["complete"] = True
        save()
        print("PaNasMs 0.2.1 active; preferences, wallpapers and data mounts preserved.", flush=True)
    except BaseException:
        print("Migration failed; restoring previous installation.", flush=True)
        restore(backup)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", type=Path)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--check", action="store_true")
    group.add_argument("--apply", action="store_true")
    group.add_argument("--rollback", type=Path)
    args = parser.parse_args()
    if args.rollback:
        restore(args.rollback.resolve())
    elif args.artifacts is None:
        parser.error("--artifacts is required")
    elif args.check:
        preflight(args.artifacts.resolve())
        print("Preflight passed; no changes made.")
    else:
        migrate(args.artifacts.resolve())


if __name__ == "__main__":
    main()
