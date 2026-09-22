import uuid
import fcntl
import stat
import zipfile
import job_control
from common import *

ROOT = Path("/var/lib/panasms-modules")
REGISTRY = ROOT / "registry.json"
UPLOADS = Path("/var/lib/panasms-agent/module-uploads")
KEYS = Path("/etc/panasms/module-keys")
UNITS = Path("/etc/systemd/system")
CORE = "0.2.6"
ACTIONS = {"module.recover", "module.install", "module.enable", "module.disable", "module.remove"}


def identifier(value):
    require(
        isinstance(value, str) and re.fullmatch(r"[a-z][a-z0-9-]{1,39}", value),
        'Invalid module identifier',
    )
    require(
        value
        not in ("core", "users", "storage", "settings", "system", "history", "sharing", "modules", "network"),
        'The identifier belongs to the core',
    )
    return value


def version(value):
    require(
        isinstance(value, str) and re.fullmatch(r"\d+\.\d+\.\d+", value),
        'Version must use X.Y.Z format',
    )
    return tuple(map(int, value.split(".")))


def satisfies(actual, required):
    current = version(actual)
    require(isinstance(required, str) and len(required) <= 100, 'Invalid version constraint')
    for part in required.split(","):
        m = re.fullmatch(r"\s*(>=|<=|>|<|=)?\s*(\d+\.\d+\.\d+)\s*", part)
        require(m, 'Use version constraints such as >=0.1.0,<1.0.0')
        other = version(m[2])
        if not {
            ">=": current >= other,
            "<=": current <= other,
            ">": current > other,
            "<": current < other,
            "=": current == other,
        }[m[1] or "="]:
            return False
    return True


def registry():
    return json.loads(REGISTRY.read_text()) if REGISTRY.exists() else {}


def save_registry(data):
    atomic(REGISTRY, json.dumps(data, ensure_ascii=False), 0o644)


def manifest(m):
    identifier(m.get("id"))
    version(m.get("version"))
    require(
        m.get("api") == 1 and satisfies(CORE, m.get("core")),
        'Module is incompatible with PaNasMs core ' + CORE,
    )
    require(
        m.get("architecture") in ("all", command(["dpkg", "--print-architecture"]).strip()),
        'The archive targets another architecture',
    )
    require(
        isinstance(m.get("title"), str) and 0 < len(m["title"]) <= 100,
        'Invalid module title',
    )
    require(m.get("service") in (None, "bin/server"), 'Unknown service format')
    require(
        isinstance(m.get("dependencies", {}), dict) and len(m.get("dependencies", {})) <= 32,
        'Invalid dependencies',
    )
    for dep, constraint in m.get("dependencies", {}).items():
        identifier(dep)
        satisfies("0.0.0", constraint)
    require(
        isinstance(m.get("packages", {}), dict) and len(m.get("packages", {})) <= 64,
        'Invalid system dependencies',
    )
    require(isinstance(m.get("widgets", {}), dict), 'Invalid widget description')
    for kind, size in m.get("widgets", {}).items():
        require(
            kind.startswith(m["id"] + ":") and re.fullmatch(r"[a-z0-9:-]{1,80}", kind),
            'Widget names must use the module prefix',
        )
        require(
            isinstance(size, list)
            and len(size) == 2
            and all(type(v) == int and 1 <= v <= 2 for v in size),
            'The widget size must fit a mobile screen',
        )
    require(
        m.get("userShell", False) in (True, False),
        'Invalid user-shell capability',
    )
    for package, minimum in m.get("packages", {}).items():
        require(re.fullmatch(r"[a-z0-9][a-z0-9+.-]{0,79}", package), 'Invalid OS package name')
        require(
            isinstance(minimum, str) and re.fullmatch(r"[a-zA-Z0-9.+:~_-]{1,100}", minimum),
            'Invalid OS package version',
        )
    require(isinstance(m.get("files"), dict) and 0 < len(m["files"]) <= 2000, 'Module has no files')
    for path, digest in m["files"].items():
        require(
            path in ("LICENSE", "NOTICE")
            or (re.fullmatch(r"(ui|bin|backend)/[a-zA-Z0-9_./-]+", path)
                and all(p not in ("", ".", "..") for p in path.split("/"))),
            'Invalid path in module',
        )
        require(re.fullmatch(r"[a-f0-9]{64}", digest), 'Invalid checksum')
    for kind in ("actions", "queries"):
        require(isinstance(m.get(kind, []), list), 'Invalid module handlers')
        for value in m.get(kind, []):
            prefix = "file" if m["id"] == "files" and kind == "actions" else m["id"]
            require(
                isinstance(value, str) and (value == prefix or value.startswith(prefix + ".")),
                'Handlers must use the module prefix',
            )
    require("ui/index.js" in m["files"], 'Module UI is missing')
    require(
        not m.get("service") or m["service"] in m["files"], 'Service executable is missing'
    )
    return m


def upload_path(token, user):
    require(
        isinstance(token, str) and re.fullmatch(r"[a-f0-9]{32}", token), 'Upload the archive again'
    )
    path = UPLOADS / (user + "-" + token + ".zip")
    require(
        path.is_file() and not path.is_symlink(),
        'Archive not found or belongs to another user',
    )
    return path


def inspect_bundle(path):
    result = {}
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        require(
            len(infos) <= 6000 and sum(i.file_size for i in infos) <= 256 * 1024 * 1024,
            'Archive too large',
        )
        names = [i.filename for i in infos]
        require(len(names) == len(set(names)), 'Archive contains duplicate paths')
        for i in infos:
            require(
                not i.is_dir()
                and not stat.S_ISLNK(i.external_attr >> 16)
                and not (i.flag_bits & 1),
                'Archive must contain only regular, unencrypted files',
            )
            require(
                not i.filename.startswith("/")
                and all(p not in ("", ".", "..") for p in i.filename.split("/")),
                'Unsafe archive path',
            )
        require(
            "bundle.json" in names and archive.getinfo("bundle.json").file_size <= 4096,
            'Archive manifest is missing',
        )
        requested = json.loads(archive.read("bundle.json")).get("root")
        identifier(requested)
        consumed = {"bundle.json"}
        for name in names:
            if not re.fullmatch(r"modules/[a-z][a-z0-9-]{1,39}/manifest.json", name):
                continue
            raw = archive.read(name)
            require(len(raw) <= 256 * 1024, 'Module manifest too large')
            m = json.loads(raw)
            identifier(m.get("id"))
            prefix = "modules/" + m["id"] + "/"
            require(name == prefix + "manifest.json", 'Identifier does not match directory')
            signer = m.get("signer", "")
            require(re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", signer), 'Publisher not specified')
            key = KEYS / (signer + ".pem")
            require(key.is_file(), 'Unknown publisher: ' + signer)
            signature = archive.read(prefix + "signature")
            require(len(signature) == 64, 'Invalid signature')
            with tempfile.TemporaryDirectory() as tmp:
                a, b = Path(tmp) / "manifest", Path(tmp) / "signature"
                a.write_bytes(raw)
                b.write_bytes(signature)
                try:
                    command(
                        [
                            "openssl",
                            "pkeyutl",
                            "-verify",
                            "-pubin",
                            "-inkey",
                            str(key),
                            "-rawin",
                            "-in",
                            str(a),
                            "-sigfile",
                            str(b),
                        ]
                    )
                except Rejected:
                    raise Rejected('Invalid module signature: ' + m["id"])
            manifest(m)
            consumed.update((name, prefix + "signature"))
            for relative, digest in m["files"].items():
                full = prefix + relative
                require(
                    full in names and hashlib.sha256(archive.read(full)).hexdigest() == digest,
                    'Corrupted file: ' + relative,
                )
                consumed.add(full)
            result[m["id"]] = m
        require(
            set(names) == consumed and requested in result,
            'Archive contains unknown files or is missing its root module',
        )
    return requested, result


def resolve(requested, available, installed):
    visiting, visited, order = set(), set(), []

    def visit(mid, constraint=None):
        require(mid not in visiting, 'Dependency cycle: ' + mid)
        candidate = available.get(mid) or installed.get(mid)
        require(candidate, 'Missing module ' + mid + '. Upload an archive containing this dependency.')
        require(
            not constraint or satisfies(candidate["version"], constraint),
            'Incompatible dependency version for ' + mid + ': requires ' + str(constraint),
        )
        if mid in visited:
            return
        visiting.add(mid)
        for dep, required in candidate.get("dependencies", {}).items():
            visit(dep, required)
        visiting.remove(mid)
        visited.add(mid)
        if mid in available or not candidate.get("enabled"):
            order.append(mid)

    visit(requested)
    future = {**installed, **{mid: available[mid] for mid in order if mid in available}}
    for mid, m in future.items():
        for dep, constraint in m.get("dependencies", {}).items():
            require(
                dep in future and satisfies(future[dep]["version"], constraint),
                'Update would break a dependency of module ' + mid + ' on ' + dep,
            )
    return order


def package_plan(manifests):
    required = {}
    for m in manifests:
        for package, minimum in m.get("packages", {}).items():
            old = required.get(package)
            if (
                not old
                or subprocess.run(["dpkg", "--compare-versions", minimum, "gt", old]).returncode
                == 0
            ):
                required[package] = minimum
    missing = []
    for package, minimum in required.items():
        found = subprocess.run(
            ["dpkg-query", "-W", "-f=${db:Status-Status} ${Version}", package],
            capture_output=True,
            text=True,
        )
        bits = found.stdout.split()
        if (
            len(bits) == 2
            and bits[0] == "installed"
            and subprocess.run(["dpkg", "--compare-versions", bits[1], "ge", minimum]).returncode
            == 0
        ):
            continue
        policy = command(["apt-cache", "policy", package])
        match = re.search(r"Candidate:\s+(\S+)", policy)
        require(
            match
            and match[1] != "(none)"
            and subprocess.run(["dpkg", "--compare-versions", match[1], "ge", minimum]).returncode
            == 0,
            'OS repositories have no suitable package '
            + package
            + " >= "
            + minimum
            + '. Refresh OS package lists.',
        )
        missing.append(package + "=" + match[1])
    changes = []
    if missing:
        simulation = command(
            ["apt-get", "--simulate", "--no-remove", "install", *missing], timeout=60
        )
        require(
            not any(line.startswith("Remv ") for line in simulation.splitlines()),
            'Dependencies require removing system packages',
        )
        changes = [line for line in simulation.splitlines() if line.startswith("Inst ")]
    return missing, changes


def unit(mid):
    return "panasms-module-" + mid + ".service"


def dependents(mid, installed):
    return [key for key, m in installed.items() if key != mid and mid in m.get("dependencies", {})]


def require_idle(mid, installed):
    if not installed.get(mid, {}).get("enabled") or not installed[mid].get("service"):
        return
    import socket
    import http.client

    conn = http.client.HTTPConnection("localhost", timeout=3)
    conn.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    conn.sock.settimeout(3)
    try:
        conn.sock.connect("/run/panasms-modules/" + mid + ".sock")
        conn.request("GET", "/health")
        response = json.loads(conn.getresponse().read())
        require(
            response.get("active") == 0,
            "Module " + mid + ' is busy: close the terminal or finish file transfers',
        )
    except (ConnectionRefusedError, FileNotFoundError):
        pass
    finally:
        conn.close()


def list_modules():
    data = registry()
    return {
        "core": CORE,
        "api": 1,
        "installed": [{**m, "requiredBy": dependents(mid, data)} for mid, m in data.items()],
    }


def plan(action, p, user):
    if action == 'module.recover':
        journal = transaction_path() / 'journal.json'
        require(journal.exists(), 'No module transaction needs recovery')
        return {'target': 'modules', 'confirmation': 'modules',
                'details': ['Recover the recorded module transaction; installed OS dependencies are retained'],
                'fingerprint': fingerprint(action, p, journal.read_text())}
    installed = registry()
    if action == "module.install":
        path = upload_path(p.get("upload"), user)
        requested, available = inspect_bundle(path)
        order = resolve(requested, available, installed)
        for mid in order:
            require_idle(mid, installed)
        manifests = [available.get(mid) or installed[mid] for mid in order]
        packages, changes = package_plan(manifests)
        details = [('Update (remains disabled): ' if m['id'] == requested and installed.get(requested, {}).get('enabled') is False else 'Install/enable: ') + m['title'] + ' ' + m['version'] for m in manifests]
        details += ['OS packages: ' + line for line in changes]
        details += [
            'Publishers: ' + ", ".join(sorted({m["signer"] for m in manifests})),
            "The module's server code runs with root privileges. Application operations run with user privileges.",
        ]
        state = [installed, hashlib.sha256(path.read_bytes()).hexdigest(), packages, changes]
        target = requested
    else:
        target = identifier(p.get("target"))
        require(target in installed, 'Module not installed')
        m = installed[target]
        if action in ("module.disable", "module.remove"):
            blockers = dependents(target, installed)
            require(not blockers, 'Dependent modules: ' + ", ".join(blockers))
            require_idle(target, installed)
        if action == "module.enable":
            manifest(m)
            order = resolve(target, {}, installed)
            items = [manifest(installed[mid]) for mid in order]
            packages, changes = package_plan(items)
        details = [
            m["title"],
            {
                "module.enable": 'Enable module and its dependencies',
                "module.disable": 'Disable module',
                "module.remove": 'Remove module code; settings and user files are preserved',
            }[action],
        ]
        state = installed
        if action == "module.enable":
            details += ['Enable: ' + item["title"] for item in items]
            details += ['OS packages: ' + line for line in changes]
            state = [installed, packages, changes]
    return {
        "target": target,
        "details": details,
        "confirmation": target,
        "fingerprint": fingerprint(action, p, state),
    }


def write_unit(m):
    if not m.get("service"):
        return
    mid = m["id"]
    content = f"""[Unit]
Description=PaNasMs module {mid}
After=local-fs.target
[Service]
User=root
Group=panasms
AmbientCapabilities=CAP_SETUID CAP_SETGID
EnvironmentFile=/etc/panasms/panasms.env
Environment=PYTHONPATH=/usr/lib/panasms/management
ExecStart={ROOT / mid / 'bin/server'}
Restart=on-failure
RestartSec=3
RuntimeDirectory=panasms-modules
RuntimeDirectoryMode=0750
RuntimeDirectoryPreserve=yes
KillMode=control-group
UMask=0077
NoNewPrivileges={'no' if m.get('userShell') else 'yes'}
PrivateTmp=yes
LockPersonality=yes
[Install]
WantedBy=multi-user.target
"""
    atomic(UNITS / unit(mid), content, 0o644)


def activate(m):
    if m.get("service"):
        write_unit(m)
        command(["systemctl", "daemon-reload"])
        command(["systemctl", "enable", "--now", unit(m["id"])])
        for attempt in range(20):
            import socket, http.client

            conn = http.client.HTTPConnection("localhost", timeout=1)
            conn.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            conn.sock.settimeout(1)
            try:
                conn.sock.connect("/run/panasms-modules/" + m["id"] + ".sock")
                conn.request("GET", "/health")
                require(conn.getresponse().status == 200, 'Module service failed to start')
                return
            except OSError:
                time.sleep(0.25)
            finally:
                conn.close()
        raise Rejected('Module service failed to start: ' + m["id"])


def transaction_path():
    return ROOT / ".transaction"


def write_transaction(data):
    atomic(transaction_path() / "journal.json", json.dumps(data), 0o600)


def recover():
    staging = transaction_path()
    journal = staging / "journal.json"
    if not journal.exists():
        if staging.exists():
            shutil.rmtree(staging)
        return
    state = json.loads(journal.read_text())
    if not state.get("committed"):
        before = state["before"]
        for mid in reversed(state["affected"]):
            identifier(mid)
            command(["systemctl", "disable", "--now", unit(mid)], accepted=(0, 1, 5))
            old = staging / ("old-" + mid)
            dest = ROOT / mid
            if old.exists():
                if dest.exists():
                    shutil.rmtree(dest)
                old.rename(dest)
            elif mid not in before and dest.exists():
                shutil.rmtree(dest)
            if mid in before:
                write_unit(before[mid])
                if before[mid].get("enabled"):
                    activate(before[mid])
            else:
                (UNITS / unit(mid)).unlink(missing_ok=True)
        save_registry(before)
        command(["systemctl", "daemon-reload"])
    shutil.rmtree(staging)


def remember_widgets(installed):
    # Retain dimensions after removal so saved user layouts remain valid.
    path = ROOT / "catalog.json"
    known = json.loads(path.read_text()) if path.exists() else {}
    for mid, item in installed.items():
        known[mid] = {"id": mid, "widgets": item.get("widgets", {})}
    atomic(path, json.dumps(known), 0o644)


def execute(action, p, user):
    ROOT.mkdir(parents=True, exist_ok=True, mode=0o755)
    with (ROOT / ".lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        recover()
        if action == 'module.recover':
            return {'message': 'Module transaction recovered'}
        installed = registry()
        before = json.loads(json.dumps(installed))
        available, path = {}, None
        if action in ("module.disable", "module.remove"):
            requested = identifier(p["target"])
            require(requested in installed, 'Module not installed')
            require(not dependents(requested, installed), 'Module is used by other modules')
            order = [requested]
            manifests = []
        else:
            if action == "module.install":
                path = upload_path(p["upload"], user)
                requested, available = inspect_bundle(path)
            else:
                requested = identifier(p["target"])
            order = resolve(requested, available, installed)
            manifests = [available.get(mid) or installed[mid] for mid in order]
            for item in manifests:
                manifest(item)
            packages, _ = package_plan(manifests)
            if packages:
                command(["apt-get", "-y", "--no-remove", "install", *packages], timeout=1800)
        staging = transaction_path()
        staging.mkdir(mode=0o700)
        state = {"before": before, "affected": order, "committed": False}
        write_transaction(state)
        try:
            gate = json.loads(json.dumps(installed))
            for mid in order:
                if mid in gate:
                    gate[mid]["enabled"] = False
            save_registry(gate)
            try:
                for mid in order:
                    require_idle(mid, before)
            except Exception:
                save_registry(before)
                shutil.rmtree(staging)
                raise
            job_control.capability(True)
            job_control.checkpoint()
            if path:
                with zipfile.ZipFile(path) as archive:
                    for mid in order:
                        if mid not in available:
                            continue
                        for relative in available[mid]["files"]:
                            job_control.checkpoint()
                            dest = staging / mid / relative
                            dest.parent.mkdir(parents=True, exist_ok=True)
                            for parent in (dest.parent, *dest.parent.parents):
                                if parent == staging: break
                                parent.chmod(0o755)
                            dest.write_bytes(archive.read("modules/" + mid + "/" + relative))
                            dest.chmod(0o755 if relative == "bin/server" else 0o644)
            job_control.capability(False)
            job_control.checkpoint()
            for mid in order:
                if before.get(mid, {}).get("service"):
                    command(["systemctl", "disable", "--now", unit(mid)])
                dest = ROOT / mid
                if action == "module.remove" or mid in available:
                    if dest.exists():
                        dest.rename(staging / ("old-" + mid))
                if action == "module.remove":
                    del installed[mid]
                    (UNITS / unit(mid)).unlink(missing_ok=True)
                elif action == "module.disable":
                    installed[mid]["enabled"] = False
                else:
                    if mid in available:
                        (staging / mid).rename(dest)
                    enabled = action != "module.install" or mid != requested or before.get(mid, {}).get("enabled", True)
                    installed[mid] = {**(available.get(mid) or installed[mid]), "enabled": enabled,
                                      "installation": before.get(mid, {}).get("installation") or uuid.uuid4().hex}
                    if enabled:
                        activate(installed[mid])
                    elif installed[mid].get("service"):
                        write_unit(installed[mid])
            command(["systemctl", "daemon-reload"])
            remember_widgets(installed)
            save_registry(installed)
            state["committed"] = True
            write_transaction(state)
        except Exception:
            job_control.capability(False)
            recover()
            raise
        recover()
        if path:
            path.unlink(missing_ok=True)
        return {
            "message": ("Module updated; remains disabled" if action == "module.install" and not installed[requested]["enabled"] else {"module.remove": 'Module removed', "module.disable": 'Module disabled'}.get(
                action, 'Modules installed and enabled'
            )),
            "modules": order,
        }


def load_operations(kind, name):
    installed = registry()
    result = []
    for mid, m in installed.items():
        if (
            not m.get("enabled")
            or name not in m.get(kind, [])
            or "backend/operations.py" not in m.get("files", {})
        ):
            continue
        import importlib.util

        path = ROOT / mid / "backend/operations.py"
        spec = importlib.util.spec_from_file_location("panasms_module_" + mid, path)
        module = importlib.util.module_from_spec(spec)
        sys.path.insert(0, str(path.parent))
        spec.loader.exec_module(module)
        result.append(module)
    return result


if __name__ == "__main__":
    require(sys.argv[1:] == ["--recover"], 'Unknown command')
    ROOT.mkdir(parents=True, exist_ok=True)
    ROOT.chmod(0o755)
    with (ROOT / ".lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        recover()
