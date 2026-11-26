"""Fixed read-only guest collector; shipped over stdin, never installed."""

import datetime
import json
import math
import os
import re
import selectors
import shutil
import subprocess
import sys
import time

UNIT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.@-]{0,127}\.service\Z")
PROPERTIES = ("Id", "LoadState", "ActiveState", "SubState", "Result",
              "ExecMainCode", "ExecMainStatus")
ITEM_BYTES = 65536


def read_command(argv, deadline):
    """Bound both output and wall time, including a producer that never exits."""
    remaining = min(7, deadline - time.monotonic())
    if remaining <= 0:
        return {"status": "partial", "text": "", "truncated": True,
                "remote_completion": "not_started"}
    process = subprocess.Popen(
        ["timeout", "--signal=TERM", "--kill-after=2s", "5s", *argv],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL,
    )
    content = bytearray()
    truncated = False
    stderr_present = False
    bytes_seen = 0
    end = time.monotonic() + remaining
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            selector.register(process.stderr, selectors.EVENT_READ)
            while selector.get_map() and time.monotonic() < end:
                for key, _ in selector.select(min(0.1, max(0, end - time.monotonic()))):
                    chunk = os.read(key.fileobj.fileno(), 8192)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    available = ITEM_BYTES - bytes_seen
                    bytes_seen += min(len(chunk), available)
                    if key.fileobj is process.stdout:
                        content.extend(chunk[:available])
                    else:
                        stderr_present = True
                    if len(chunk) > available:
                        truncated = True
                        break
                if truncated:
                    break
            if not selector.get_map() and not truncated:
                try:
                    process.wait(timeout=max(0.001, end - time.monotonic()))
                except subprocess.TimeoutExpired:
                    pass
        if process.poll() is None:
            truncated = True
            process.terminate()
            try:
                process.wait(timeout=0.2)
            except subprocess.TimeoutExpired:
                process.kill()
        code = process.wait(timeout=1)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        process.stdout.close()
        process.stderr.close()
    return {"status": "partial" if truncated or code or stderr_present else "ok",
            "remote_completion": "unknown" if truncated or code in (124, 137) else "observed",
            "text": content.decode("utf-8", errors="replace"), "truncated": truncated}


def collect(request):
    """Only failed services and a small current-boot journal window."""
    end = datetime.datetime.now(datetime.timezone.utc)
    try:
        start = datetime.datetime.fromisoformat(request["started_at"].replace("Z", "+00:00"))
        if start.tzinfo is None:
            raise ValueError("Timezone required")
        start_epoch, end_epoch = start.timestamp(), end.timestamp()
        if (not all(math.isfinite(value) for value in (start_epoch, end_epoch))
                or not 0 <= start_epoch <= end_epoch):
            raise ValueError("Invalid epoch window")
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError):
        return {"status": "unavailable", "reason": "invalid_time_window", "items": [],
                "remote_completion": "not_started"}
    if any(not shutil.which(tool) for tool in ("timeout", "systemctl", "journalctl")):
        return {"status": "unavailable", "reason": "missing_guest_tool", "items": [],
                "remote_completion": "not_started"}
    deadline = time.monotonic() + min(29, max(0, request["remaining"]))
    discovery = read_command(
        ["systemctl", "--failed", "--type=service", "--no-legend", "--plain", "--no-pager"],
        deadline,
    )
    units = []
    for line in discovery["text"].splitlines():
        name = line.split()[0] if line.split() else ""
        if UNIT.fullmatch(name) and name not in units:
            units.append(name)
    skipped = len(units) > 4
    items = []
    completions = [discovery["remote_completion"]]
    for unit in units[:4]:
        show = read_command(
            ["systemctl", "show", "--no-pager",
             "--property=" + ",".join(PROPERTIES), "--", unit], deadline,
        )
        # Even a nonconforming systemctl cannot return extra properties.
        show["text"] = "\n".join(
            line for line in show["text"].splitlines()
            if line.partition("=")[0] in PROPERTIES
        )
        journal = read_command(
            ["journalctl", "--boot=0", "--no-pager", "--output=short-iso",
             "--lines=100", f"--since=@{start_epoch:.6f}", f"--until=@{end_epoch:.6f}",
             "--unit=" + unit], deadline,
        )
        completions.extend(item["remote_completion"] for item in (show, journal))
        items.extend([{"unit": unit, "kind": "show", **show},
                      {"unit": unit, "kind": "journal", **journal}])
    partial = skipped or discovery["status"] != "ok" or any(
        item["status"] != "ok" for item in items
    )
    return {"status": "partial" if partial else "ok", "items": items,
            "remote_completion": ("not_started" if all(item == "not_started" for item in completions)
                                  else "observed" if all(item == "observed" for item in completions)
                                  else "unknown"),
            "reason": "systemd_discovery_unavailable" if discovery["status"] != "ok" else None,
            "units_truncated": skipped, "collected_at": end.isoformat()}


def main():
    try:
        request = json.loads(sys.stdin.buffer.read(4097))
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        response = {"status": "unavailable", "reason": "guest_collection_failed", "items": [],
                    "remote_completion": "not_started"}
    else:
        try:
            response = collect(request)
        except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
            response = {"status": "unavailable", "reason": "guest_collection_failed", "items": [],
                        "remote_completion": "unknown"}
    print(json.dumps(response, ensure_ascii=True))


if __name__ == "__main__":
    main()
