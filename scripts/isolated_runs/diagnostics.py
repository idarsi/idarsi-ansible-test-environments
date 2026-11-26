"""Default-off, bounded failure evidence. Never an authority for cleanup."""

import datetime
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import selectors
import shlex
import subprocess
import sys
import time
import uuid
import xml.etree.ElementTree as ET

from . import admission
from .backends import LABEL, REPO, kvm_instance
from .discovery import PODMAN, VIRSH
from .state import RunError, lock, private_directory

PROFILE = "systemd-failed-v1"
CAPABILITY = "failure_diagnostics:v1"
LIMIT = 1024 * 1024
POLICY = {
    "profile": PROFILE, "capability": CAPABILITY, "services": 4, "journal_lines": 100,
    "item_bytes": 65536, "total_bytes": LIMIT, "seconds": 30, "operation_seconds": 5,
    "properties": ["Id", "LoadState", "ActiveState", "SubState", "Result",
                   "ExecMainCode", "ExecMainStatus"],
}
DIGEST = hashlib.sha256(json.dumps(POLICY, sort_keys=True).encode()).hexdigest()
GUEST_SOURCE = (Path(__file__).with_name("diagnostics_guest.py")).read_text()
# Constant remote command, no target, unit or timestamp interpolation.
REMOTE_COMMAND = shlex.join(["python3", "-c", GUEST_SOURCE])
UNIT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.@-]{0,127}\.service\Z")


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def sanitize(text):
    """Best effort only: remove terminal controls and common credential formats."""
    text = "".join(character for character in str(text)
                   if character in "\n\t" or (character.isprintable()
                                              and character not in "\u202a\u202b\u202d\u202e\u2066\u2067\u2068\u2069"))
    text = re.sub(r"-----BEGIN [^-]*PRIVATE KEY-----.*?(?:-----END [^-]*PRIVATE KEY-----|$)",
                  "[REDACTED PRIVATE KEY]", text, flags=re.S)
    text = re.sub(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/-]+=*", r"\1 [REDACTED]", text)
    text = re.sub(
        r'''(?i)(["']?\b(?:password|passwd|secret|token|api[_-]?key|client[_-]?secret|authorization)\b["']?\s*[:=]\s*)("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^\s,;}]+)''',
        r"\1[REDACTED]", text,
    )
    text = re.sub(r"(://)[^/\s:@]+:[^/\s@]+@", r"\1[REDACTED]@", text)
    return text


def bounded(argv, deadline, payload=None, cap=65536, seconds=5):
    """No shell, inherited session, bounded pipes; supervisor settles descendants."""
    remaining = min(seconds, deadline - time.monotonic())
    if remaining <= 0:
        return {"status": "partial", "stdout": b"", "truncated": False,
                "remote_completion": "not_started"}
    process = subprocess.Popen(
        argv, stdin=subprocess.PIPE if payload is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    output = [bytearray(), bytearray()]
    truncated = False
    completed = False
    end = time.monotonic() + remaining
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ, 0)
            selector.register(process.stderr, selectors.EVENT_READ, 1)
            pending = memoryview(payload or b"")
            if payload is not None:
                os.set_blocking(process.stdin.fileno(), False)
                selector.register(process.stdin, selectors.EVENT_WRITE, 2)
            while selector.get_map() and time.monotonic() < end:
                for key, _ in selector.select(min(0.1, max(0, end - time.monotonic()))):
                    if key.data == 2:
                        try:
                            pending = pending[os.write(key.fileobj.fileno(), pending[:4096]):]
                        except BrokenPipeError:
                            pending = memoryview(b"")
                        if not pending:
                            selector.unregister(key.fileobj)
                            key.fileobj.close()
                        continue
                    chunk = os.read(key.fileobj.fileno(), 8192)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    available = cap - sum(map(len, output))
                    output[key.data].extend(chunk[:available])
                    if len(chunk) > available:
                        truncated = True
                        break
                if truncated:
                    break
            if not selector.get_map():
                try:
                    process.wait(timeout=max(0.001, end - time.monotonic()))
                    completed = True
                except subprocess.TimeoutExpired:
                    pass
        if not completed:
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
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None and not stream.closed:
                stream.close()
    # Never persist stderr (even transport errors can contain secrets).
    return {"status": "ok" if completed and not code else "partial",
            "stdout": bytes(output[0]), "truncated": truncated or not completed,
            "exit_code": code,
            "captured_bytes": sum(map(len, output)),
            "remote_completion": "observed" if completed else "unknown"}


def query(argv, deadline):
    response = bounded(argv, deadline)
    if response["status"] != "ok" or response["truncated"]:
        raise RunError("diagnostic_identity_unavailable")
    return response["stdout"].decode("utf-8")


def transport(data, guest, ready, deadline):
    """Use exact durable backend IDs only; never discover a replacement by name."""
    if ready.get("instance") != guest["logical"]:
        raise RunError("diagnostic_ready_binding_invalid")
    if data["backend"] == "podman":
        identity = guest["id"]
        if not isinstance(identity, str) or re.fullmatch(r"[0-9a-f]{64}", identity) is None:
            raise RunError("diagnostic_full_container_id_required")
        # Pinned local context, checked without using the unbounded discovery helper.
        if os.getuid() == 0 or any(os.environ.get(key) for key in (
            "CONTAINER_HOST", "CONTAINER_CONNECTION", "DOCKER_HOST",
        )):
            raise RunError("diagnostic_podman_context_invalid")
        info = json.loads(query(PODMAN + ["info", "--format", "json"], deadline))
        context = {"uid": os.getuid(), "graph_root": info["store"]["graphRoot"],
                   "run_root": info["store"]["runRoot"],
                   "network_backend": info["host"]["networkBackend"]}
        if (info["host"]["security"]["rootless"] is not True
                or context != data["context"]["podman"]):
            raise RunError("diagnostic_podman_context_changed")
        actual = json.loads(query(PODMAN + ["inspect", identity], deadline))
        if (len(actual) != 1 or actual[0]["Id"] != identity
                or actual[0]["Config"].get("Labels", {}).get(LABEL) != data["id"]):
            raise RunError("diagnostic_container_ownership_invalid")
        return PODMAN + ["exec", "-i", identity, "python3", "-c", GUEST_SOURCE]
    identity = guest["id"]
    if str(uuid.UUID(identity)) != identity or data["context"]["libvirt"] != "qemu:///system":
        raise RunError("diagnostic_domain_identity_invalid")
    root = ET.fromstring(query(VIRSH + ["dumpxml", identity], deadline))
    if (root.findtext("uuid") != identity or root.findtext("name") != guest["name"]
            or root.findtext("description") != "idarsi-run:" + data["id"]):
        raise RunError("diagnostic_domain_ownership_invalid")
    platforms = data["config"]["platforms"]
    matches = [(index, platform) for index, platform in enumerate(platforms)
               if platform["name"] == guest["logical"]]
    if len(matches) != 1:
        raise RunError("diagnostic_platform_binding_invalid")
    index, platform = matches[0]
    if ready != kvm_instance(platform, data["subnet"], index,
                             Path(data["_directory"]) / "kvm_ed25519"):
        raise RunError("diagnostic_ready_binding_invalid")
    address = str(ipaddress.IPv4Address(ready["address"]))
    if ipaddress.IPv4Address(address) not in ipaddress.IPv4Network(data["subnet"]):
        raise RunError("diagnostic_address_invalid")
    if (re.fullmatch(r"[a-z_][a-z0-9_-]{0,30}", ready["user"]) is None
            or str(ready["port"]) != "22"
            or ready["identity_file"] != str(Path(data["_directory"]) / "kvm_ed25519")):
        raise RunError("diagnostic_ssh_binding_invalid")
    return ["ssh", "-F", "/dev/null", "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ForwardAgent=no", "-o", "ForwardX11=no",
            "-o", "ControlMaster=no", "-o", "ControlPath=none", "-o", "ControlPersist=no",
            "-o", "IdentitiesOnly=yes", "-o", "ConnectTimeout=5",
            "-o", "ConnectionAttempts=1", "-o", "ServerAliveInterval=2",
            "-o", "ServerAliveCountMax=1", "-i", ready["identity_file"],
            "-p", "22", ready["user"] + "@" + address, REMOTE_COMMAND]


def evidence(response):
    """Whitelist the guest response, sanitize BEFORE writing any evidence."""
    value = json.loads(response["stdout"])
    if not isinstance(value, dict) or value.get("status") not in ("ok", "partial", "unavailable"):
        raise ValueError("invalid guest report")
    items = value.get("items")
    if not isinstance(items, list) or len(items) > 8:
        raise ValueError("invalid guest items")
    result = []
    units = {item.get("unit") for item in items if isinstance(item, dict)
             and isinstance(item.get("unit"), str)}
    if len(units) > 4:
        raise ValueError("too many guest services")
    for item in items:
        if (not isinstance(item, dict) or not isinstance(item.get("unit"), str)
                or not UNIT.fullmatch(item["unit"]) or item.get("kind") not in ("show", "journal")
                or item.get("status") not in ("ok", "partial")
                or not isinstance(item.get("text"), str)):
            raise ValueError("invalid guest item")
        raw = item["text"].encode("utf-8")
        text = sanitize(raw[:65536].decode("utf-8", errors="replace"))
        if item["kind"] == "show":
            text = "\n".join(line for line in text.splitlines()
                             if line.partition("=")[0] in POLICY["properties"])
        else:
            text = "\n".join(text.splitlines()[-100:])
        text = text.encode("utf-8")[:65536].decode("utf-8", errors="ignore")
        result.append({"unit": item["unit"], "kind": item["kind"], "text": text,
                       "status": item["status"], "truncated": bool(item.get("truncated"))
                       or len(raw) > 65536})
    completion = value.get("remote_completion")
    if completion not in ("observed", "unknown", "not_started"):
        completion = "unknown"
    return {"status": value["status"], "items": result,
            "remote_completion": completion,
            "reason": value.get("reason") if value.get("reason") in (
                "invalid_time_window", "missing_guest_tool", "guest_collection_failed",
                "systemd_discovery_unavailable") else None,
            "units_truncated": bool(value.get("units_truncated"))}


def worker(store, run_id, attempt):
    """Journalled read-only worker; no admission opening or mutation operation."""
    from .processes import boot_id, process

    data = store.load(run_id)
    request = data.get("failure_diagnostics", {})
    current = process(os.getsid(0))
    if (request.get("attempt") != attempt or request.get("profile_digest") != DIGEST
            or request.get("state") != "accepted"
            or request.get("worker", {}).get("pid") != os.getsid(0)
            or current is None or request["worker"]["start"] != current["start"]
            or request["worker"]["boot"] != boot_id()
            or request["worker"] not in data["workers"]
            or data.get("mode") != "supervised" or data.get("mutation_protocol") != "sealed-v1"
            or admission.gate(store, run_id)["state"] != "closed"):
        raise RunError("diagnostic_worker_not_authorized")
    # Leave a small margin inside the supervisor's 30-second envelope to stop
    # the local transport and persist a partial/unknown report on timeout.
    deadline = time.monotonic() + 27
    data["_directory"] = str(store.directory(run_id))
    report = {key: request[key] for key in (
        "profile", "profile_digest", "original_exit", "started_at", "source",
    )}
    report.update(schema="idarsi.failure-diagnostics/v1", run_uuid=run_id,
                  role=data["role"], scenario=data["scenario"], backend=data["backend"],
                  collection_started_at=now(), guests=[])
    ready = {item["instance"]: item for item in data.get("instances_ready", [])}
    budget = LIMIT - 32768
    captured_bytes = 0
    for guest in data["guests"]:
        if guest["logical"] not in ready:
            continue
        if (len(json.dumps(report).encode()) >= budget or time.monotonic() >= deadline
                or captured_bytes >= LIMIT):
            report["truncated"] = True
            break
        item = {"logical_guest": guest["logical"], "backend_id": guest["id"],
                "transport_trust": ("owned_local_podman" if data["backend"] == "podman"
                                    else "provisioning_ssh_unverified_host_key"),
                "remote_completion": "not_started", "status": "unavailable", "items": []}
        try:
            argv = transport(data, guest, ready[guest["logical"]], deadline)
            payload = json.dumps({"started_at": request["started_at"],
                                  "remaining": max(0, deadline - time.monotonic())}).encode()
            response = bounded(argv, deadline, payload,
                               cap=min(600000, LIMIT - captured_bytes), seconds=30)
            captured_bytes += response.get("captured_bytes", len(response["stdout"]))
            # Local ssh/exec exit (including 255/connection failure) is not
            # remote completion evidence. Only a valid guest receipt can
            # establish observed completion.
            item["remote_completion"] = "unknown"
            item["truncated"] = response["truncated"]
            if response["status"] == "ok" and not response["truncated"]:
                item.update(evidence(response))
            else:
                item["status"] = "unavailable" if response.get("exit_code") in (126, 127) else "partial"
                item["reason"] = "guest_python_or_transport_unavailable"
        except (RunError, OSError, ValueError, KeyError, TypeError, ET.ParseError,
                subprocess.SubprocessError):
            # Fixed finite reason, never backend stderr/exception details.
            item["reason"] = "collection_unavailable"
        if len(json.dumps(report).encode()) + len(json.dumps(item).encode()) > budget:
            item.update(items=[], status="partial", truncated=True)
        report["guests"].append(item)
    report["collection_finished_at"] = now()

    def clean(value):
        if isinstance(value, str):
            return sanitize(value)
        if isinstance(value, list):
            return [clean(item) for item in value]
        if isinstance(value, dict):
            return {key: clean(item) for key, item in value.items()}
        return value

    report = clean(report)
    directory = private_directory(store.directory(run_id) / "diagnostics")
    # Refuse replacement, including dangling symlinks. Private trusted run parent.
    destination = directory / "systemd-failed-v1.json"
    if destination.exists() or destination.is_symlink():
        raise RunError("diagnostic_artifact_already_exists")
    content = json.dumps(report, sort_keys=True, ensure_ascii=True).encode()
    if len(content) > LIMIT:
        raise RunError("diagnostic_artifact_budget_exceeded")
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fd = os.open(destination.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=descriptor)
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def source_identity(role):
    """Local provenance only, bounded and never exposing command stderr."""
    result = {}
    deadline = time.monotonic() + 5
    for name, path in (("helper", REPO), ("role", role)):
        try:
            revision = query(["git", "-C", str(path), "rev-parse", "HEAD"], deadline).strip()
            dirty = bool(query(["git", "-C", str(path), "status", "--porcelain"], deadline).strip())
            result[name + "_revision"] = revision if re.fullmatch(r"[0-9a-f]{40,64}", revision) else None
            result[name + "_dirty"] = dirty
        except (RunError, OSError, ValueError):
            result[name + "_revision"] = None
            result[name + "_dirty"] = None
    result["tool_identity"] = "idarsi-test-run/failure_diagnostics:v1"
    result["collector_sha256"] = hashlib.sha256(GUEST_SOURCE.encode()).hexdigest()
    return result


def collect_before_cleanup(store, run_id, original_exit, cancelled):
    """Existing barriers before and after a distinct diagnostic session."""
    from .context import require_completed
    from .cooperative_stop import drain_mutations
    from .processes import spawn, stop_workers

    data = store.load(run_id)
    if not data.get("failure_diagnostics") or not 0 < original_exit <= 255 or cancelled():
        return
    # Failures here must keep existing retention semantics; caller still invokes
    # ordinary cleanup, which repeats the same barriers and never trusts reports.
    data = drain_mutations(store, run_id)
    stop_workers(data)
    if cancelled():
        return
    with lock(store.directory(run_id) / ".resources.lock", blocking=False):
        data = store.load(run_id)
        require_completed(data)
        if not data.get("instances_ready"):
            return
        request = data["failure_diagnostics"]
        request.update(attempt=str(uuid.uuid4()), state="accepted", original_exit=original_exit)
        ready = {instance["instance"] for instance in data["instances_ready"]}
        request["targets"] = [
            {"logical_guest": guest["logical"], "backend_id": guest["id"]}
            for guest in data["guests"] if guest["logical"] in ready
        ]
        child = spawn(
            store, data,
            [sys.executable, str(REPO / "scripts/test-run"), "_diagnostics", run_id, request["attempt"]],
            dict(os.environ), str(REPO), operation=request,
        )
    deadline = time.monotonic() + 30
    try:
        while child.poll() is None and not cancelled() and time.monotonic() < deadline:
            time.sleep(0.05)
    finally:
        # This is LOCAL transport/session settlement only. Remote command proof
        # is intentionally NOT a prerequisite for deleting an already-owned VM.
        stop_workers(store.load(run_id))
        child.wait()
    try:
        if child.returncode == 0:
            print("Failure diagnostics: " + run_id + " / diagnostics/systemd-failed-v1.json "
                  "(best-effort retained evidence; not cleanup authority)", flush=True)
        else:
            print("Failure diagnostics unavailable or interrupted; original exit preserved.", flush=True)
    except OSError:
        pass  # A closed log pipe never becomes cleanup authority.
