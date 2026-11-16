"""Cheap isolation contract tests: no libvirt, Podman or Molecule execution."""

import contextlib
import io
import ipaddress
import json
import multiprocessing
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch
import uuid
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from isolated_runs import cli, discovery, processes
from isolated_runs.backends import Backend, LABEL, validate_platforms
from isolated_runs.state import RunError, Store, lock


def reserve(root, results):
    store = Store(Path(root))
    run = store.allocate("podman", {}, lambda: [], Path("/role"), "podman-validation")
    results.put(run["subnet"])


class StoreFixture(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.store = Store(Path(self.temporary.name))

    def allocate(self):
        return self.store.allocate("podman", {}, lambda: [], Path("/role"), "validation")


class StoreTests(StoreFixture):
    def test_concurrent_allocations_across_store_instances(self):
        context = multiprocessing.get_context("fork")
        queue = context.Queue()
        workers = [
            context.Process(target=reserve, args=(self.temporary.name, queue))
            for _ in range(8)
        ]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(10)
            self.assertEqual(worker.exitcode, 0)
        networks = [queue.get(timeout=2) for _ in workers]
        self.assertEqual(len(set(networks)), 8)
        for run in self.store.runs():
            self.assertEqual(run["uid"], os.getuid())
            self.assertTrue(self.store.ephemeral(run["id"]).is_dir())

    def test_discovery_failure_allocates_nothing(self):
        with self.assertRaises(RunError):
            self.store.allocate(
                "kvm", {}, lambda: (_ for _ in ()).throw(RunError("query failed")),
                Path("/role"), "validation",
            )
        self.assertEqual(self.store.runs(), [])

    def test_route_and_outstanding_lease_excluded(self):
        first = self.allocate()
        second = self.store.allocate(
            "kvm", {}, lambda: [ipaddress.ip_network("10.0.1.0/24")],
            Path("/role"), "validation",
        )
        self.assertEqual(first["subnet"], "10.0.0.0/24")
        self.assertEqual(second["subnet"], "10.0.2.0/24")

    def test_cleaned_lease_can_be_reused(self):
        first = self.allocate()
        first["status"] = "cleaned"
        self.store.save(first)
        self.assertEqual(self.allocate()["subnet"], first["subnet"])

    def test_nonprivate_state_refused(self):
        root = Path(self.temporary.name) / "shared"
        root.mkdir(mode=0o755)
        with self.assertRaises(RunError):
            Store(root)

    def test_symlink_lock_refused(self):
        path = Path(self.temporary.name) / ".lock"
        path.symlink_to("/dev/null")
        with self.assertRaises(OSError), lock(path):
            pass

    def test_cleanup_failure_retains_lease_and_manifest(self):
        run = self.allocate()
        with patch.object(Backend, "destroy_guests", side_effect=RunError("not owned")):
            with self.assertRaises(RunError):
                cli.cleanup(self.store, run["id"])
        self.assertEqual(self.store.load(run["id"])["status"], "cleanup_failed")
        self.assertNotEqual(self.allocate()["subnet"], run["subnet"])

    def test_cleanup_does_not_run_while_supervisor_locked(self):
        run = self.allocate()
        with lock(self.store.directory(run["id"]) / ".supervisor.lock"):
            with self.assertRaises(RunError):
                cli.cleanup(self.store, run["id"])

    def test_workers_stop_before_guest_disk_network_and_lease(self):
        run = self.allocate()
        order = []
        with patch.object(cli, "stop_workers", side_effect=lambda data: order.append("workers")), \
                patch.object(Backend, "destroy_guests", side_effect=lambda: order.append("guests")), \
                patch.object(Backend, "destroy_network", side_effect=lambda: order.append("network")):
            cli.cleanup(self.store, run["id"])
        self.assertEqual(order, ["workers", "guests", "network"])
        self.assertEqual(self.store.load(run["id"])["status"], "cleaned")


class DiscoveryTests(unittest.TestCase):
    def test_addresses_routes_and_inactive_networks(self):
        def fake(argv, **kwargs):
            if argv[:3] == ["ip", "-j", "address"]:
                return json.dumps([{"addr_info": [{"family": "inet", "local": "10.1.2.3", "prefixlen": 24}]}])
            if argv[:3] == ["ip", "-j", "-4"]:
                return json.dumps([{"dst": "default"}, {"dst": "172.16.0.0/16", "table": 123}])
            self.fail("Unexpected command " + repr(argv))

        inactive = ET.fromstring("<network><ip address='192.168.42.1' netmask='255.255.255.0'/></network>")
        with patch.object(discovery, "command", side_effect=fake), \
                patch.object(discovery, "podman_context", return_value={}), \
                patch.object(discovery, "libvirt_networks", return_value=[inactive]), \
                patch.object(discovery, "podman_networks", return_value=[{"subnets": [{"subnet": "10.42.0.0/24"}]}]):
            result = {str(network) for network in discovery.discover()}
        self.assertEqual(result, {"10.1.2.0/24", "172.16.0.0/16", "192.168.42.0/24", "10.42.0.0/24"})

    def test_libvirt_query_failure_is_not_empty_network_list(self):
        with patch.object(discovery, "command", side_effect=RunError("permission denied")):
            with self.assertRaises(RunError):
                discovery.libvirt_networks()

    def test_all_definitions_are_requested(self):
        with patch.object(discovery, "command", return_value="") as call:
            self.assertEqual(discovery.libvirt_networks(), [])
        self.assertIn("--all", call.call_args.args[0])

    def test_podman_query_failure_is_not_empty_network_list(self):
        with patch.object(discovery, "command", side_effect=RunError("connection failed")):
            with self.assertRaises(RunError):
                discovery.podman_networks()


class OwnershipTests(StoreFixture):
    def backend(self):
        run = self.allocate()
        run["network"] = {"name": "owned-network", "id": "immutable-network-id"}
        self.store.save(run)
        return Backend(self.store, run)

    def test_same_name_replacement_network_is_not_removed(self):
        backend = self.backend()
        actual = {"name": "owned-network", "id": "foreign", "labels": {LABEL: backend.data["id"]}}
        with patch("isolated_runs.backends.podman_networks", return_value=[actual]):
            with self.assertRaises(RunError):
                backend.destroy_network()

    def test_pending_network_reconciles_only_matching_label(self):
        backend = self.backend()
        backend.data["network"]["id"] = None
        actual = {"name": "owned-network", "id": "created-id", "labels": {LABEL: backend.data["id"]}}
        with patch("isolated_runs.backends.podman_networks", return_value=[actual]):
            backend.owned_podman_network()
        self.assertEqual(self.store.load(backend.data["id"])["network"]["id"], "created-id")
        actual["labels"] = {}
        with patch("isolated_runs.backends.podman_networks", return_value=[actual]):
            with self.assertRaises(RunError):
                backend.owned_podman_network()

    def test_container_replacement_is_not_removed(self):
        backend = self.backend()
        guest = {"name": "owned", "id": "old-id"}
        actual = {"Name": "owned", "Id": "new-id", "Config": {"Labels": {LABEL: backend.data["id"]}}}
        with patch("isolated_runs.backends.command", side_effect=["new-id", json.dumps([actual])]):
            with self.assertRaises(RunError):
                backend.owned_container(guest)

    def test_domain_replacement_is_not_removed(self):
        backend = self.backend()
        guest = {"name": "owned", "id": str(uuid.uuid4()), "disk": None}
        with patch("isolated_runs.backends.command", side_effect=[str(uuid.uuid4()), "owned"]):
            with self.assertRaises(RunError):
                backend.owned_domain(guest)

    def test_disk_replacement_preserved(self):
        path = Path(self.temporary.name) / "disk"
        path.write_text("foreign")
        info = path.stat()
        with self.assertRaises(RunError):
            Backend.verify_disk({"path": str(path), "device": info.st_dev, "inode": info.st_ino + 1})
        self.assertTrue(path.exists())

    def test_transient_network_absent_after_reboot_is_safe(self):
        backend = self.backend()
        backend.data["backend"] = "kvm"
        with patch("isolated_runs.backends.libvirt_networks", return_value=[]):
            backend.destroy_network()
        self.assertIsNone(backend.data["network"])

    def test_network_rm_never_forced(self):
        backend = self.backend()
        with patch.object(backend, "owned_podman_network", side_effect=[True, None]), \
                patch("isolated_runs.backends.command", return_value="") as command:
            backend.destroy_network()
        self.assertEqual(command.call_args.args[0][-3:], ["network", "rm", "immutable-network-id"])

    def test_transient_network_uuid_is_durable_before_create(self):
        run = self.allocate()
        run["backend"] = "kvm"
        backend = Backend(self.store, run)

        def create(argv, **kwargs):
            self.assertEqual(argv[-2], "net-create")
            network = self.store.load(run["id"])["network"]
            root = ET.parse(argv[-1]).getroot()
            self.assertEqual(root.findtext("uuid"), network["id"])
            self.assertLessEqual(len(root.find("bridge").get("name")), 15)
            self.assertEqual(root.find("ip").get("address"), "10.0.0.1")
            self.assertEqual(root.find("./ip/dhcp/range").get("start"), "10.0.0.210")
            return ""

        with patch.object(backend, "check_context"), patch.object(backend.storage, "probe"), \
                patch("isolated_runs.backends.libvirt_networks", return_value=[]), \
                patch("isolated_runs.backends.command", side_effect=create):
            backend.network()

    def test_container_intent_precedes_create_and_actual_id_is_recorded(self):
        backend = self.backend()
        guest = {"name": "physical", "logical": "logical", "id": None}
        backend.data["guests"].append(guest)
        backend.save()
        commands = []

        def create(argv, **kwargs):
            commands.append(argv)
            if "create" in argv:
                self.assertIsNone(self.store.load(backend.data["id"])["guests"][0]["id"])
                self.assertIn(LABEL + "=" + backend.data["id"], argv)
                return "immutable-container-id"
            return ""

        with patch.object(backend, "owned_container", side_effect=[None, {}]), \
                patch("isolated_runs.backends.command", side_effect=create):
            instance = backend.create_container(guest, {
                "name": "logical", "image": "prebuilt", "command": ["/bin/sleep", "infinity"],
            })
        self.assertEqual(self.store.load(backend.data["id"])["guests"][0]["id"], "immutable-container-id")
        self.assertEqual(instance["instance"], "logical")
        self.assertEqual(instance["address"], "physical")
        self.assertEqual(instance["connection"], "containers.podman.podman")
        self.assertEqual(commands[-1][-2:], ["start", "immutable-container-id"])


class ValidationTests(unittest.TestCase):
    def test_podman_common_prebuilt_scope(self):
        result = validate_platforms("podman", [{
            "name": "node", "image": "localhost/test:latest",
            "pre_build_image": True, "command": "/bin/sleep infinity",
        }], Path("/scenario"))
        self.assertEqual(result[0]["command"], ["/bin/sleep", "infinity"])

    def test_unsafe_options_rejected_before_backend_mutation(self):
        for key, value in (
            ("network_mode", "host"), ("volumes", ["/:/host"]), ("privileged", True),
            ("published_ports", ["2222:22"]), ("capabilities", ["SYS_ADMIN"]),
            ("extra_opts", ["--pid=host"]), ("networks", ["default"]),
        ):
            with self.subTest(key=key), self.assertRaises(RunError):
                validate_platforms("podman", [{
                    "name": "node", "image": "test", "pre_build_image": True, key: value,
                }], Path("/scenario"))

    def test_legacy_default_ip_fields_rejected(self):
        with self.assertRaises(RunError):
            validate_platforms("kvm", [{
                "name": "node", "image_path": "/base.qcow2", "ipv4_address": "192.168.250.10",
            }], Path("/scenario"))

    def test_no_implicit_container_build(self):
        with self.assertRaises(RunError):
            validate_platforms("podman", [{"name": "node", "image": "test"}], Path("/scenario"))

    def test_cli_help(self):
        with contextlib.redirect_stdout(io.StringIO()) as output, self.assertRaises(SystemExit) as exit_:
            cli.main(["--help"])
        self.assertEqual(exit_.exception.code, 0)
        self.assertIn("cleanup", output.getvalue())

    def test_legacy_launchers_are_guarded_in_managed_context(self):
        scripts = Path(__file__).resolve().parents[1] / "scripts"
        for script, args in (("kvm-vm", ["destroy", "node"]), ("kvm-base-image", ["ensure"])):
            result = subprocess.run(
                ["bash", str(scripts / script)] + args,
                env=dict(os.environ, IDARSI_RUN_ID=str(uuid.uuid4())),
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("Managed runs", result.stderr)


class WorkerTests(StoreFixture):
    def test_start_gate_journals_before_execute_and_stops_worker(self):
        run = self.allocate()
        marker = Path(self.temporary.name) / "executed"
        child = processes.spawn(self.store, run, [
            sys.executable, "-c",
            "import time; from pathlib import Path; Path(" + repr(str(marker))
            + ").write_text('started'); time.sleep(60)",
        ], dict(os.environ), self.temporary.name)
        try:
            saved = self.store.load(run["id"])
            self.assertEqual(saved["workers"][0]["pid"], child.pid)
            processes.stop_workers(saved)
            child.wait(timeout=5)
            self.assertFalse(processes.members(saved["workers"][0]))
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()

    def test_previous_boot_never_signals_reused_pid(self):
        self.assertEqual(processes.members({"boot": "previous-boot", "pid": os.getpid(), "start": "0"}), [])

    def test_reused_pid_fails_closed(self):
        with self.assertRaises(RunError):
            processes.members({"boot": processes.boot_id(), "pid": os.getpid(), "start": "invalid"})

    def test_missing_leader_does_not_hide_surviving_session_member(self):
        worker = {"boot": processes.boot_id(), "pid": 987654, "start": "1"}
        fake = {"pid": 123, "session": worker["pid"], "uid": os.getuid(), "zombie": False, "start": "2"}
        with patch.object(processes, "process", side_effect=[None, fake]), \
                patch.object(Path, "iterdir", return_value=[Path("/proc/123")]):
            self.assertEqual(processes.members(worker), [fake])


class SupervisorTests(StoreFixture):
    def invoke(self, code=0, cleanup_error=False, interrupt=False):
        child = SimpleNamespace(returncode=code, pid=123)
        child.poll = lambda: None if interrupt else code
        child.wait = lambda **kwargs: code

        def fake_spawn(*args):
            if interrupt:
                os.kill(os.getpid(), signal.SIGTERM)
            return child

        args = SimpleNamespace(role=self.temporary.name, scenario="validation", backend="podman")
        config = {"platforms": [{"name": "node", "image": "test", "pre_build_image": True}]}
        with patch.object(cli, "parse_configuration", return_value=config), \
                patch.object(cli.shutil, "which", return_value="/mock/tool"), \
                patch.object(cli, "podman_context", return_value={}), \
                patch.object(cli, "discover", return_value=[]), \
                patch.object(cli, "spawn", side_effect=fake_spawn), \
                patch.object(cli, "stop_workers"), \
                patch.object(Backend, "destroy_guests", side_effect=RunError("cleanup failed") if cleanup_error else None), \
                patch.object(Backend, "destroy_network"), \
                contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            return cli.run(args, self.store)

    def test_original_failure_preserved(self):
        self.assertEqual(self.invoke(code=7), 7)

    def test_cleanup_error_changes_success_to_failure(self):
        self.assertNotEqual(self.invoke(cleanup_error=True), 0)
        self.assertEqual(self.store.runs()[0]["status"], "cleanup_failed")

    def test_cleanup_error_does_not_hide_original_failure(self):
        self.assertEqual(self.invoke(code=7, cleanup_error=True), 7)

    def test_signal_sets_nonzero_and_restores_handler(self):
        before = signal.getsignal(signal.SIGTERM)
        self.assertEqual(self.invoke(interrupt=True), 128 + signal.SIGTERM)
        self.assertEqual(signal.getsignal(signal.SIGTERM), before)

    def test_crash_recovery_uses_durable_worker_session(self):
        run = self.allocate()
        child = processes.spawn(
            self.store, run, [sys.executable, "-c", "import time; time.sleep(60)"],
            dict(os.environ), self.temporary.name,
        )
        try:
            # A fresh store/supervisor has no Popen state: explicit recovery uses
            # only durable birth/session records, as after original supervisor loss.
            other_store = Store(Path(self.temporary.name))
            with patch.object(Backend, "destroy_guests"), patch.object(Backend, "destroy_network"):
                cli.cleanup(other_store, run["id"])
            child.wait(timeout=5)
            self.assertEqual(other_store.load(run["id"])["status"], "cleaned")
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()


if __name__ == "__main__":
    unittest.main()
