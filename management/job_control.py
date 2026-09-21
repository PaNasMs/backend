from contextlib import suppress
import json
import os
import subprocess
import sys
import signal
import time


class Cancelled(Exception):
    pass


def capability(allowed):
    if 'PANASMS_CONTROL_FD' in os.environ:
        print(json.dumps({'cancellable': allowed}), file=sys.stderr, flush=True)


def checkpoint():
    value = os.environ.get('PANASMS_CONTROL_FD')
    if value is None:
        return
    fd = int(value)
    os.set_blocking(fd, False)
    try:
        requested = os.read(fd, 1)
    except BlockingIOError:
        return
    if requested or requested == b"":
        capability(False)
        raise Cancelled()


def copying(args, timeout=86400):
    """Only for copy-to-staging commands whose caller owns rollback."""
    capability(True)
    process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, start_new_session=True, env={**os.environ, 'LC_ALL': 'C'})
    started = time.monotonic()
    try:
        while True:
            checkpoint()
            try:
                out, err = process.communicate(timeout=.25)
                if process.returncode:
                    raise RuntimeError('Copy command failed')
                return out
            except subprocess.TimeoutExpired:
                if time.monotonic() - started > timeout:
                    raise RuntimeError('Copy command timed out')
    finally:
        if process.poll() is None:
            with suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGTERM)
            try:
                process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                with suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGKILL)
                process.communicate()
        capability(False)
