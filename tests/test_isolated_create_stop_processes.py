"""Owned Python checkpoint sessions and mocked exact-UUID hard VM teardown."""

from contextlib import ExitStack
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
import uuid
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from isolated_runs import admission, backends, cli, context, cooperative_stop, processes
from isolated_runs.state import RunError, Store
from isolated_runs.storage import Storage


def wait_for(predicate, timeout=5):
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() >= deadline:
            raise AssertionError("Create-stop fixture synchronization timed out")
        time.sleep(0.01)


def child_create(root, run_id):
    store = Store(Path(root))
    directory = store.directory(run_id)
    for key in list(os.environ):
        if key.startswith("IDARSI_HANDOFF"):
            del os.environ[key]
    os.environ.update(
        IDARSI_RUN_ID=run_id, IDARSI_HANDOFF="v1",
        MOLECULE_EPHEMERAL_DIRECTORY=str(store.ephemeral(run_id)),
    )

    def terminated(*_):
        operation = store.load(run_id)["operations"][0]
        if operation.get("outcome") != "stopped" or operation.get("completion") != operation["id"]:
            raise RuntimeError("Session signalled before stopped-create seal")
        (directory / "session-stopped").touch()
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, terminated)

    def create(backend, _platforms):
        key = directory / "kvm_ed25519"
        key.write_text("fixture-placeholder")
        Path(str(key) + ".pub").write_text("fixture-placeholder")
        kickstart = directory / "fixture.ks"
        kickstart.write_text("@@SSH_USER@@ @@SSH_PUBLIC_KEY@@ @@NETWORK_CONFIGURATION@@")
        guest = {
            "name": "fixture-guest", "id": str(uuid.uuid4()), "logical": "fixture",
            "disks": [{"path": str(directory / "fixture.qcow2"), "serial": "itr-root"}],
        }
        backend.data.update(network={"name": "fixture-network"}, guests=[guest])
        backend.save()
        platform = {
            "name": "fixture", "ssh_user": "fixture", "install_source": "fixture-iso", "kickstart": str(kickstart),
            "disk_size_gb": 1, "memory_mb": 512, "vcpus": 1, "install_timeout": 3600,
        }
        return [backend.provision_domain(guest, platform, 0)]

    def command(argv, **_kwargs):
        if argv[0] != "virt-install":
            raise AssertionError("Unexpected backend command: " + repr(argv))
        (directory / "host-start-entered").touch()
        # Model a successful start RPC returning after the supervisor closes
        # admission. No subprocess or actual hypervisor command is invoked.
        wait_for(lambda: admission.gate(store, run_id)["state"] == "closed")
        (directory / "host-start-returned").touch()
        return ""

    with patch.object(context, "resolved", return_value=({}, {})), patch.object(
        backends.Backend, "create", new=create
    ), patch.object(backends.Backend, "disk_command"), patch.object(
        backends.Backend, "verify_disk"
    ), patch.object(backends, "image_chain", return_value={"fixture": True}), patch.object(
        backends, "command", side_effect=command,
    ):
        try:
            cli.lifecycle(store, "create", run_id)
        except RunError as exc:
            if "stopped cooperatively" not in str(exc):
                raise
        else:
            raise AssertionError("Stopped create unexpectedly succeeded")
    (directory / "create-returned").touch()
    time.sleep(12)
    raise RuntimeError("Fixture session was not stopped within its lifetime bound")


def child_cleanup(root, run_id, operation_id):
    store = Store(Path(root))
    directory = store.directory(run_id)

    def expired(*_):
        raise RuntimeError("Fixture cleanup exceeded its lifetime bound")

    signal.signal(signal.SIGALRM, expired)
    signal.alarm(8)

    def destroy_guests():
        data = store.load(run_id)
        first = data["operations"][0]
        if first.get("outcome") != "stopped" or first.get("completion") != first["id"]:
            raise AssertionError("Cleanup entered without stopped-create seal")
        if any(processes.members(worker) for worker in data["workers"][:-1]):
            raise AssertionError("Cleanup entered with the create session still alive")
        if not (directory / "session-stopped").exists():
            raise AssertionError("Missing real create-session termination evidence")
        data["guests"] = []
        store.save(data)
        (directory / "guests-removed").touch()

    def destroy_network():
        if not (directory / "guests-removed").exists():
            raise AssertionError("Network cleanup preceded guest cleanup")
        data = store.load(run_id)
        data["network"] = None
        store.save(data)
        (directory / "network-removed").touch()

    with patch.object(context, "Backend") as backend:
        backend.return_value.destroy_guests.side_effect = destroy_guests
        backend.return_value.destroy_network.side_effect = destroy_network
        context.worker(store, run_id, operation_id, "destroy")


class CreateStopTests(unittest.TestCase):
    @unittest.skipUnless(
        sys.platform == "linux" and hasattr(os, "pidfd_open")
        and hasattr(signal, "pidfd_send_signal"),
        "Linux procfs and pidfd signalling are required",
    )
    def test_readiness_checkpoint_seals_before_session_stop_and_sealed_cleanup(self):
        with tempfile.TemporaryDirectory(prefix="create-stop-") as temporary, ExitStack() as stack:
            store = Store(Path(temporary) / "state")
            data = store.allocate("kvm", {}, lambda: [], Path(temporary), "checkpoint-fixture")
            run_id = data["id"]
            directory = store.directory(run_id)
            data.update(
                mode="supervised", status="running", mutation_protocol="sealed-v1",
                admission_protocol=admission.PROTOCOL, config={"platforms": []},
                operations=[], workers=[],
            )
            store.save(data)
            admission.initialize(store, run_id)
            children = []
            log = stack.enter_context((directory / "children.log").open("w"))
            real_spawn = processes.spawn
            real_drain = cooperative_stop.drain_mutations

            def drain(current_store, current_id):
                return real_drain(current_store, current_id, timeout=5)

            def spawn(current_store, current_data, _argv, env, cwd, operation=None):
                # Substitute only the backend-mocking child entry point.
                # Production spawn still gates and journals each real session.
                child = real_spawn(
                    current_store, current_data,
                    [sys.executable, "-B", str(Path(__file__).resolve()), "--cleanup",
                     str(store.root), run_id, operation["id"]],
                    env, cwd, operation=operation,
                )
                children.append(child)
                return child

            try:
                child = subprocess.Popen(
                    [sys.executable, "-B", str(Path(__file__).resolve()), "--create",
                     str(store.root), run_id],
                    stdin=subprocess.PIPE, stdout=log, stderr=log, start_new_session=True,
                )
                children.append(child)
                # The initial process waits on stdin before importing authority.
                identity = processes.process(child.pid)
                self.assertIsNotNone(identity)
                data["workers"] = [
                    {"pid": child.pid, "start": identity["start"], "boot": processes.boot_id()}
                ]
                store.save(data)
                child.stdin.write(b"go\n")
                child.stdin.flush()
                wait_for(lambda: (directory / "host-start-entered").exists())
                self.assertNotIn("completion", store.load(run_id)["operations"][0])
                with patch.object(cli, "spawn", side_effect=spawn), patch.object(
                    cooperative_stop, "drain_mutations", side_effect=drain,
                ):
                    cli.cleanup(store, run_id)
                final = store.load(run_id)
                self.assertEqual("cleaned", final["status"])
                self.assertNotIn("instances_ready", final)
                create, cleanup = final["operations"]
                self.assertEqual("stopped", create["outcome"])
                self.assertEqual("guest-readiness", create["stop_checkpoint"])
                self.assertEqual(create["id"], create["completion"])
                self.assertEqual("supervisor-cleanup", cleanup["purpose"])
                self.assertEqual(cleanup["id"], cleanup["completion"])
                for marker in ("host-start-returned", "session-stopped", "guests-removed", "network-removed"):
                    self.assertTrue((directory / marker).exists(), marker)
                self.assertFalse(any(processes.members(worker) for worker in final["workers"]))
                self.assertTrue(all(child.wait(timeout=2) == 0 for child in children))
            except Exception as exc:
                raise AssertionError(
                    "Owned checkpoint fixture failed:\n" + (directory / "children.log").read_text()
                ) from exc
            finally:
                for child in children:
                    if child.poll() is None:
                        child.terminate()
                    try:
                        child.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        child.wait(timeout=2)
                    finally:
                        if child.stdin is not None:
                            child.stdin.close()

    def test_running_owned_vm_is_hard_destroyed_by_uuid_before_undefine_and_storage(self):
        with tempfile.TemporaryDirectory(prefix="hard-destroy-") as temporary:
            root = Path(temporary)
            store = Store(root / "state")
            data = store.allocate("kvm", {}, lambda: [], root, "destroy-fixture")
            peer = store.allocate("kvm", {}, lambda: [], root, "foreign-peer")
            peer_before = store.load(peer["id"])
            backend = backends.Backend(store, data)
            backend.storage = Storage(root)
            disk = {"path": str(root / ("itr-" + uuid.uuid4().hex + ".qcow2"))}
            with backend.storage.publish(disk, lambda: None):
                pass
            owned_id, foreign_id = str(uuid.uuid4()), str(uuid.uuid4())
            guest = {"id": owned_id, "name": "owned-fixture", "disks": [disk]}
            backend.data["guests"] = [guest]
            foreign_xml = (
                "<domain><name>foreign-peer</name><uuid>" + foreign_id
                + "</uuid><devices/></domain>"
            )
            events = []

            def command(argv):
                self.assertEqual(backends.VIRSH, argv[:len(backends.VIRSH)])
                args = argv[len(backends.VIRSH):]
                if args == ["domstate", owned_id]:
                    return "running"
                if args in (["destroy", owned_id], ["undefine", owned_id]):
                    self.assertTrue(Path(disk["path"]).exists())
                    events.append(args[0])
                    return ""
                if args in (["list", "--uuid"], ["list", "--all", "--persistent", "--uuid"],
                            ["list", "--all", "--uuid"]):
                    return foreign_id
                if args in (["dumpxml", foreign_id], ["dumpxml", foreign_id, "--inactive"]):
                    return foreign_xml
                raise AssertionError("Unexpected or foreign-mutating command: " + repr(argv))

            remove = backend.storage.remove

            def remove_disk(record):
                self.assertEqual(["destroy", "undefine"], events)
                events.append("storage-remove")
                remove(record)

            with patch.object(backend, "check_context"), patch.object(
                backend, "owned_domain", side_effect=[ET.Element("domain"), None]
            ), patch.object(backends, "command", side_effect=command), patch.object(
                backend.storage, "remove", side_effect=remove_disk,
            ):
                backend.destroy_guests()
            self.assertEqual(["destroy", "undefine", "storage-remove"], events)
            self.assertFalse(Path(disk["path"]).exists())
            self.assertEqual([], store.load(data["id"])["guests"])
            self.assertEqual(peer_before, store.load(peer["id"]))


if __name__ == "__main__":
    if sys.argv[1:2] == ["--create"]:
        if sys.stdin.readline() != "go\n":
            raise RuntimeError("Missing fixture start token")
        child_create(*sys.argv[2:])
    elif sys.argv[1:2] == ["--cleanup"]:
        child_cleanup(*sys.argv[2:])
    else:
        unittest.main()
