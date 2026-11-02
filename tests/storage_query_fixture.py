"""Offline legacy oracle for GO-08 parity fixtures; never probes host devices."""
import json
import os
from pathlib import Path
import sys
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "management"))
import storage


def main():
    request = json.load(sys.stdin)
    root = Path(request["root"])
    inventory = {key: request["inventory"][key] for key in request["order"]}
    real_path = Path
    media, schedule, schedules = storage.media_info, storage.smart_schedule, storage.smart_schedules

    def mapped_path(value):
        value = str(value)
        if value.startswith("/sys/class/block"):
            return root / "sys" / value.removeprefix("/sys/class/block").lstrip("/")
        if value == "/etc/fstab":
            return root / "fstab"
        raise AssertionError("Unexpected legacy filesystem access: " + value)

    with patch.object(storage, "inventory", return_value=inventory), \
         patch.object(storage, "Path", side_effect=mapped_path), \
         patch.object(storage, "FSTAB", root / "fstab"), \
         patch.object(storage, "media_info", side_effect=lambda row: media(row, root / "sys")), \
         patch.object(storage, "smart_schedule", side_effect=lambda serial, *args: schedule(serial, root / "units")), \
         patch.object(storage, "smart_schedules", side_effect=lambda serial: schedules(serial, root / "units")), \
         patch.object(storage.filesystem_health, "cached", return_value=None), \
         patch.object(storage.disk_sleep, "query", return_value={"sleepSettings": {"minutes": 0}, "sleepStatus": {}, "sleepRuntime": {"status": "disabled", "timerActive": True, "timerEnabled": True, "applied": 0, "total": 0}}), \
         patch.object(storage.shutil, "which", side_effect=lambda name: name if name == "mkfs.ext4" else None), \
         patch.object(storage, "command", side_effect=AssertionError("Unexpected device command")), \
         patch.object(storage, "json_command", side_effect=AssertionError("Unexpected device probe")):
        # protected() constructs Path(path).name as well as absolute sysfs paths.
        def path(value):
            value = str(value)
            if value.startswith("/dev/"):
                return real_path(value)
            return mapped_path(value)
        storage.Path.side_effect = path
        result = storage.query(request["view"], request.get("target"))
        if os.environ.get("PANASMS_VALIDATE_STORAGE_SCHEMA") == "1":
            import yaml
            from jsonschema import Draft202012Validator
            document = yaml.safe_load((real_path(__file__).resolve().parents[1] / "api/openapi.yaml").read_text())
            schema = "StorageOptions" if request["view"] == "storage-options" else "RaidCandidates"
            validator = Draft202012Validator({"$ref": "#/components/schemas/" + schema, "components": document["components"]})
            validator.validate(result)
            validator.validate(request["candidate"])
            if schema == "StorageOptions":
                validator.validate({**result, "sleepSettings": None})
        json.dump(result, sys.stdout)


if __name__ == "__main__":
    main()
