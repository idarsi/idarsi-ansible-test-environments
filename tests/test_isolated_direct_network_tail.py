"""Direct network-tail recovery boundaries; no backend or retained-state access."""

import contextlib
import copy
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from isolated_runs import cli, context, direct_network_tail as tail
from isolated_runs.state import RunError, Store, atomic_json


class OrdinaryCleanupBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.worker = {"pid": 987654, "start": "1", "boot": str(uuid.uuid4())}
        self.operation = str(uuid.uuid4())
        self.data = {
            "id": str(uuid.uuid4()), "mode": "direct", "backend": "kvm",
            "status": "running", "context_publication": "published",
            "workers": [self.worker], "guests": [],
            "network": {"id": str(uuid.uuid4()), "name": "fixture-network"},
            "instances_ready": [{"instance": "stale-mapping"}],
            "operations": [
                {"id": "create", "action": "create", "worker": self.worker, "completion": "create"},
                {"id": self.operation, "action": "destroy", "worker": self.worker},
            ],
        }

    def test_original_incomplete_destroy_is_not_an_ordinary_completion(self):
        before = copy.deepcopy(self.data)
        with patch.object(context, "members", return_value=[]):
            with self.assertRaisesRegex(RunError, "Incomplete mutation"):
                context.require_completed(self.data)
        self.assertEqual(self.data, before)
        self.assertNotIn("completion", self.data["operations"][-1])

    def test_generic_cleanup_cannot_adopt_direct_network_tail(self):
        store = Mock()
        store.load.return_value = self.data
        store.directory.return_value = Path("/fixture")
        before = copy.deepcopy(self.data)
        with patch.object(cli, "stop_workers"), \
                patch.object(cli, "lock", return_value=contextlib.nullcontext()), \
                patch.object(cli, "Backend") as backend:
            with self.assertRaisesRegex(RunError, "Incomplete mutation"):
                cli.cleanup_locked(store, self.data["id"])
            backend.assert_not_called()
        store.save.assert_not_called()
        store.allocate.assert_not_called()
        self.assertEqual(self.data, before)


class ReadOnlyDiagnosticTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent)
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.role, self.ephemeral = self.root / "role", self.root / "ephemeral"
        self.role.mkdir()
        self.ephemeral.mkdir()
        self.store = Store(self.root / "state")
        self.operation = str(uuid.uuid4())
        self.args = argparse.Namespace(
            action=tail.ACTION, backend="kvm", scenario="kvm-fixture", role=str(self.role),
            operation=self.operation, dry_run=True,
        )
        self.identity = {
            "role": str(self.role), "scenario": self.args.scenario, "backend": "kvm",
            "ephemeral_directory": str(self.ephemeral),
        }
        self.data = self.store.allocate("kvm", {"libvirt": "qemu:///system"}, lambda: [], self.role, self.args.scenario)
        self.worker = {"pid": 987654, "start": "1", "boot": str(uuid.uuid4())}
        generation = self.data["id"]
        network_id = str(uuid.uuid4())
        create = str(uuid.uuid4())
        self.data.update(
            mode="direct", status="running", context_publication="published",
            direct_identity=self.identity,
            direct_context=dict(
                self.identity, schema=context.SCHEMA, mode="direct", generation=generation,
                collections_directory=str(self.ephemeral / "collections"),
            ),
            config={
                "_idarsi_effective_role": str(self.role),
                "_idarsi_effective_scenario": self.args.scenario,
                "_idarsi_effective_ephemeral": str(self.ephemeral),
                "_idarsi_effective_env": {
                    "MOLECULE_PROJECT_DIRECTORY": str(self.role),
                    "MOLECULE_SCENARIO_DIRECTORY": str(self.role / "molecule" / self.args.scenario),
                    "MOLECULE_EPHEMERAL_DIRECTORY": str(self.ephemeral),
                },
                "platforms": [{"name": "database"}],
            },
            workers=[self.worker], guests=[],
            network={"id": network_id, "name": "itr-" + network_id.replace("-", "")[:24]},
            instances_ready=[{"instance": "database", "address": "fixture-not-authority"}],
            operations=[
                {"id": create, "action": "create", "worker": self.worker, "completion": create},
                {"id": self.operation, "action": "destroy", "worker": self.worker},
            ],
        )
        self.store.save(self.data)
        self.pointer, _ = context.pointer_path(self.store, self.identity)
        atomic_json(self.pointer, {"identity": self.identity, "generation": generation})
        for path in (
            self.pointer.with_suffix(".lock"),
            self.store.directory(generation) / ".supervisor.lock",
            self.store.directory(generation) / ".resources.lock",
        ):
            path.touch(mode=0o600, exist_ok=True)
        self.environment = {"MOLECULE_EPHEMERAL_DIRECTORY": str(self.ephemeral)}
        self.addCleanup(patch.stopall)
        patch.dict(os.environ, self.environment, clear=True).start()

    def state_snapshot(self):
        return {
            str(path.relative_to(self.root)): (
                path.lstat().st_ino, path.lstat().st_mode, path.lstat().st_mtime_ns,
                hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None,
            )
            for path in self.root.rglob("*")
        }

    def test_lost_ledger_reports_no_authority_and_performs_no_writes_or_queries(self):
        before = self.state_snapshot()
        with patch.object(self.store, "save") as save, patch.object(self.store, "allocate") as allocate, \
                patch("isolated_runs.processes.spawn") as spawn, \
                patch("isolated_runs.processes.stop_workers") as stop, \
                patch("isolated_runs.discovery.command") as command, \
                patch("subprocess.run") as subprocess, patch("os.kill") as signal:
            result = tail.inspect(self.args, self.store)
            for mutation in (save, allocate, spawn, stop, command, subprocess, signal):
                mutation.assert_not_called()
        self.assertEqual(result["blockers"], ["original_resource_identity_ledger_unavailable"])
        self.assertTrue(result["network_only_scope_insufficient_for_terminal_cleanup"])
        for flag in ("eligible", "apply_authorized", "lease_release_authorized", "audit_written"):
            self.assertIs(result[flag], False)
        self.assertNotIn("plan", result)
        self.assertNotIn("plan_digest", result)
        self.assertEqual(self.state_snapshot(), before)

    def test_main_opens_existing_store_only_and_outputs_bounded_refusal(self):
        output = io.StringIO()
        with patch.object(tail.Store, "open_existing", return_value=self.store) as existing, \
                patch.object(context, "Store") as constructor, contextlib.redirect_stdout(output):
            code = context.main([
                tail.ACTION, "--backend", "kvm", "--scenario", self.args.scenario,
                "--role", str(self.role), "--operation", self.operation, "--dry-run",
            ])
        self.assertEqual(code, 0)
        constructor.assert_not_called()
        existing.assert_called_once_with()
        self.assertFalse(json.loads(output.getvalue())["eligible"])

    def test_no_apply_force_or_other_mutation_options_exist(self):
        for option in ("--force", "--accept-profile", "--plan"):
            with self.subTest(option=option), patch.object(context, "Store") as store, \
                    contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as exit:
                    context.main([tail.ACTION, option])
                self.assertEqual(exit.exception.code, 2)
                store.assert_not_called()

    def test_source_root_is_bytes_only_never_public_location_or_eligibility(self):
        receipt = {
            "subset_digest": "fixture-approved-subset", "root": {"path": "/private/fixture/source"},
            "provenance": "reviewed-byte-subset-not-historical-execution-attestation",
        }
        args = argparse.Namespace(**dict(vars(self.args), producing_source_root="/private/fixture/source"))
        before = self.state_snapshot()
        with patch.object(tail.source, "verify_source", return_value=receipt) as verified:
            result = tail.inspect(args, self.store)
            verified.assert_called_once_with("/private/fixture/source")
        self.assertTrue(result["producing_source"]["verified"])
        self.assertNotIn("/private/fixture/source", json.dumps(result))
        self.assertFalse(result["eligible"])
        self.assertFalse(result["apply_authorized"])
        self.assertFalse(result["lease_release_authorized"])
        self.assertTrue(set(result["blockers"]) >= {
            "runtime_visibility_unavailable", "firewall_visibility_unavailable", "helper_visibility_unavailable",
        })
        self.assertEqual(result["qualification"]["status"], "not-performed-default-forensic-contract-unavailable")
        self.assertEqual(self.state_snapshot(), before)
        with patch.object(tail.source, "verify_source", side_effect=RunError("approved_producing_source_unavailable")):
            result = tail.inspect(args, self.store)
            self.assertEqual(result["blockers"], ["approved_producing_source_unavailable"])

    def test_required_modes_and_backend_rejected_before_any_store_constructor(self):
        for argv in (
            [tail.ACTION, "--backend", "kvm", "--scenario", self.args.scenario, "--operation", self.operation],
            [tail.ACTION, "--backend", "podman", "--scenario", self.args.scenario, "--operation", self.operation, "--dry-run"],
            ["destroy", "--backend", "kvm", "--scenario", self.args.scenario, "--operation", self.operation],
            [tail.ACTION, "--backend", "kvm", "--scenario", self.args.scenario, "--operation", self.operation, "--apply"],
        ):
            with self.subTest(argv=argv), patch.object(context, "Store") as store, \
                    contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(context.main(argv), 1)
                store.assert_not_called()

    def test_handoff_markers_are_invalid_even_when_empty(self):
        for key in ("IDARSI_RUN_ID", "IDARSI_HANDOFF", "IDARSI_HANDOFF_UNKNOWN"):
            with self.subTest(key=key), patch.dict(os.environ, {key: ""}):
                result = tail.inspect(self.args, self.store)
                self.assertEqual(result["blockers"], ["unsupported_direct_context_or_handoff"])
                self.assertFalse(result["eligible"])

    def test_missing_context_is_read_only_actionable_refusal(self):
        for missing in (self.pointer, self.pointer.with_suffix(".lock"), self.store.directory(self.data["id"]) / ".resources.lock"):
            with self.subTest(missing=missing.name):
                contents = missing.read_bytes()
                missing.unlink()
                before = self.state_snapshot()
                result = tail.inspect(self.args, self.store)
                self.assertFalse(result["eligible"])
                self.assertNotIn("original_resource_identity_ledger_unavailable", result["blockers"])
                self.assertEqual(self.state_snapshot(), before)
                missing.write_bytes(contents)
                missing.chmod(0o600)
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(
                tail.inspect(self.args, self.store)["blockers"], ["export_actual_molecule_ephemeral_directory"],
            )

    def test_wrong_pointer_operation_mode_and_unknown_recovery_records_fail_closed(self):
        before = copy.deepcopy(self.data)
        for key, value in (
            ("mode", "supervised"), ("status", "cleaned"), ("guests", [{"id": "unknown"}]),
            ("storage_probe", {}), ("direct_network_tail_recovery", {}),
            ("direct_identity", dict(self.identity, scenario="other")),
        ):
            with self.subTest(key=key):
                self.store.save(dict(before, **{key: value}))
                self.assertFalse(tail.inspect(self.args, self.store)["eligible"])
                self.assertNotEqual(
                    tail.inspect(self.args, self.store)["blockers"], ["original_resource_identity_ledger_unavailable"],
                )
        self.store.save(before)
        wrong = argparse.Namespace(**dict(vars(self.args), operation=str(uuid.uuid4())))
        self.assertEqual(tail.inspect(wrong, self.store)["blockers"], ["not_exact_original_incomplete_destroy"])
        atomic_json(self.pointer, {"identity": dict(self.identity, scenario="other"), "generation": self.data["id"]})
        self.assertEqual(tail.inspect(self.args, self.store)["blockers"], ["direct_context_pointer_mismatch"])

    def test_unsealed_or_malformed_earlier_guest_operation_cannot_be_adopted(self):
        original = copy.deepcopy(self.data)
        operation = {
            "id": str(uuid.uuid4()), "action": "guest-stop", "worker": self.worker,
            "protocol": context.guest_control.PROTOCOL, "guest": "database",
            "domain_uuid": str(uuid.uuid4()),
        }
        for malformed in (operation, dict(operation, completion=operation["id"], result={})):
            self.data = copy.deepcopy(original)
            self.data["operations"].insert(-1, malformed)
            self.store.save(self.data)
            result = tail.inspect(self.args, self.store)
            self.assertFalse(result["eligible"])
            self.assertNotEqual(result["blockers"], ["original_resource_identity_ledger_unavailable"])


if __name__ == "__main__":
    unittest.main()
