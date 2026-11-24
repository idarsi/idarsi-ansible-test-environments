"""Standard profile lifecycle fixtures: no host queries or real child/backend operations."""

import argparse
import contextlib
import copy
import hashlib
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uuid
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import test_isolated_direct_network_tail as diagnostic_tests
import test_isolated_network as network_tests
from isolated_runs import direct_network_tail_standard as standard
from isolated_runs import direct_network_tail_runtime as runtime
from isolated_runs.network_recovery import expected_network
from isolated_runs.state import RunError


class StandardLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.fixture = diagnostic_tests.ReadOnlyDiagnosticTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.store, self.data = self.fixture.store, self.fixture.data
        self.identity = self.fixture.identity
        self.boot = self.data["workers"][0]["boot"]
        worker = {"pid": 987655, "start": "2", "boot": self.boot}
        self.data["workers"].append(worker)
        self.data["operations"][-1]["worker"] = worker
        self.store.save(self.data)
        self.operation = self.fixture.operation
        self.args = argparse.Namespace(**dict(
            vars(self.fixture.args), profile=runtime.PROFILE, producing_source_root="/private/fixture/source",
            plan=None, accept_profile=runtime.PROFILE, apply=True,
        ))
        path = self.store.directory(self.data["id"]) / "network.xml"
        path.write_bytes(ET.tostring(expected_network(self.data), encoding="unicode").encode())
        path.chmod(0o600)
        for name in (".storage-graph.lock", ".allocator.lock"):
            (self.store.root / name).touch(mode=0o600, exist_ok=True)
        self.present, self.alive, self.in_worker = True, False, False
        self.runtime = {"profile": runtime.PROFILE, "installed": "fixture", "claims": runtime.CLAIMS}
        self.source = {
            "profile": "direct-empty-checkpoint-network-tail-v1", "subset_digest": standard.source.SUBSET_DIGEST,
            "root": {"path": self.args.producing_source_root, "device": 1, "inode": 2, "uid": os.getuid(), "mode": 0o40700},
            "provenance": "reviewed-byte-subset-not-historical-execution-attestation",
        }
        self.addCleanup(patch.stopall)
        patch.object(standard.source, "verify_source", side_effect=lambda _: copy.deepcopy(self.source)).start()
        patch.object(runtime, "controller", return_value={"prefix": "/fixture/controller", "current_source": "fixture"}).start()
        patch.object(runtime, "qualify_current_runtime", side_effect=lambda: copy.deepcopy(self.runtime)).start()
        patch.object(standard.processes, "boot_id", return_value=self.boot).start()
        patch.object(standard.recovery_system, "complete_proc_view").start()
        patch.object(standard.processes, "members", return_value=[]).start()
        patch.object(standard.processes, "process", side_effect=self.process).start()
        self.observer = patch.object(standard, "observe_network", side_effect=self.observe).start()
        self.destroy = patch.object(runtime, "destroy_exact_network", side_effect=self.destroy_network).start()
        self.spawn = patch.object(standard.processes, "spawn", side_effect=self.fake_spawn).start()

    def process(self, pid):
        if self.alive and pid == os.getpid():
            return {"pid": pid, "start": "88", "session": pid, "uid": os.getuid(), "zombie": False}
        return None

    def observe(self, data, *, require_absent=False):
        if require_absent and self.present:
            raise RunError("fixture_network_remains")
        return {"network": "present" if self.present else "absent",
                "postcondition": None if self.present else standard.absence_receipt()}

    def destroy_network(self, identity):
        self.assertEqual(identity, self.data["network"]["id"])
        self.present = False

    def fake_spawn(self, store, data, argv, env, cwd, operation):
        self.assertEqual(store.load(data["id"])[standard.KEY]["attempts"][-1]["phase"], "intent")
        worker = {"pid": os.getpid(), "start": "88", "boot": self.boot}
        operation["worker"] = worker
        data["workers"].append(worker)
        store.save(data)
        self.assertEqual(store.load(data["id"])[standard.KEY]["attempts"][-1]["worker"], worker)
        outer = self

        class Child:
            def wait(self, timeout):
                outer.assertEqual(timeout, 180)
                outer.alive, outer.in_worker = True, True
                try:
                    with patch.object(standard.os, "getsid", return_value=os.getpid()):
                        standard.worker(store, data["id"], outer.operation, operation["id"], operation["plan_digest"])
                finally:
                    outer.alive, outer.in_worker = False, False
                return 0
        return Child()

    def approve_fixture_plan(self):
        plan, _ = standard.proof(
            self.store, self.store.load(self.data["id"]), self.identity, self.operation, self.args.producing_source_root,
        )
        self.args.plan = standard.digest(plan)
        return plan

    def test_readonly_plan_has_accurate_claims_no_source_path_and_no_writes(self):
        before = self.fixture.state_snapshot()
        result = standard.inspect(self.args, self.store)
        self.assertTrue(result["eligible"], result)
        self.assertFalse(result["apply_authorized"])
        self.assertFalse(result["lease_release_authorized"])
        self.assertNotIn(self.args.producing_source_root, str(result))
        self.assertFalse(result["plan"]["claims"]["original_destroy_completed"])
        self.assertEqual(result["plan"]["claims"]["loaded_image_attestation"], "unverified")
        self.assertEqual(self.fixture.state_snapshot(), before)
        self.destroy.assert_not_called()
        self.spawn.assert_not_called()

    def test_success_requires_gated_worker_and_independent_parent_settlement(self):
        plan = self.approve_fixture_plan()
        before = copy.deepcopy(self.data["operations"])
        result = standard.apply(self.args, self.store)
        self.assertEqual(result["outcome"], "reconciled")
        final = self.store.load(self.data["id"])
        self.assertEqual(final["status"], "cleaned")
        self.assertIsNone(final["network"])
        self.assertNotIn("instances_ready", final)
        self.assertEqual(final["operations"], before)
        self.assertNotIn("completion", final["operations"][-1])
        attempt = final[standard.KEY]["attempts"][-1]
        self.assertEqual(attempt["phase"], "completed")
        self.assertEqual(attempt["settlement"], standard.settlement_receipt(plan, attempt))
        self.destroy.assert_called_once_with(self.data["network"]["id"])
        self.assertGreaterEqual(standard.source.verify_source.call_count, 6)

    def test_wrong_acceptance_digest_or_source_runtime_drift_cannot_launch(self):
        self.approve_fixture_plan()
        for field, value in (("accept_profile", "other"), ("plan", "0" * 64)):
            args = argparse.Namespace(**dict(vars(self.args), **{field: value}))
            with self.subTest(field=field), self.assertRaises(RunError):
                standard.apply(args, self.store)
        with patch.object(runtime, "qualify_current_runtime", return_value=dict(self.runtime, installed="changed")):
            with self.assertRaisesRegex(RunError, "plan_changed"):
                standard.apply(self.args, self.store)
        self.source["root"]["inode"] = 3
        with self.assertRaisesRegex(RunError, "plan_changed"):
            standard.apply(self.args, self.store)
        self.spawn.assert_not_called()
        self.assertNotIn(standard.KEY, self.store.load(self.data["id"]))

    def test_worker_failure_or_timeout_never_settles_or_releases(self):
        self.approve_fixture_plan()
        for failure in (False, True):
            with self.subTest(timeout=failure):
                class Child:
                    def wait(self, timeout):
                        if failure:
                            raise subprocess.TimeoutExpired("fixture", timeout)
                        return 1
                with patch.object(standard.processes, "spawn", return_value=Child()), \
                        patch.object(standard, "publish_terminal") as terminal:
                    with self.assertRaises(RunError):
                        standard.apply(self.args, self.store)
                    terminal.assert_not_called()
                self.assertEqual(self.store.load(self.data["id"])["status"], "running")
                self.store.save(self.data)
        self.destroy.assert_not_called()

    def test_parent_rechecks_absence_independently_of_worker_evidence(self):
        self.approve_fixture_plan()
        observe = self.observe
        def parent_failure(data, *, require_absent=False):
            if require_absent and not self.in_worker:
                raise RunError("fixture_parent_kernel_evidence_failed")
            return observe(data, require_absent=require_absent)
        with patch.object(standard, "observe_network", side_effect=parent_failure), \
                patch.object(standard, "publish_terminal") as terminal:
            with self.assertRaisesRegex(RunError, "parent_kernel"):
                standard.apply(self.args, self.store)
            terminal.assert_not_called()
        final = self.store.load(self.data["id"])
        self.assertEqual(final["status"], "running")
        self.assertEqual(final[standard.KEY]["attempts"][-1]["phase"], "resources_verified")

    def test_settlement_fsync_failure_prevents_allocator_release(self):
        self.approve_fixture_plan()
        save = self.store.save
        def fail_settlement(data):
            record = data.get(standard.KEY)
            if record and record["attempts"][-1]["phase"] == "settlement_verified":
                raise OSError("fixture fsync failure")
            save(data)
        with patch.object(self.store, "save", side_effect=fail_settlement), \
                patch.object(standard, "publish_terminal") as terminal:
            with self.assertRaises(OSError):
                standard.apply(self.args, self.store)
            terminal.assert_not_called()
        self.assertEqual(self.store.load(self.data["id"])["status"], "running")

    def test_uncertain_terminal_commit_is_explicit_and_requires_fresh_reconfirmation(self):
        self.approve_fixture_plan()
        save = self.store.save
        def fail_after_replace(data):
            save(data)
            if data["status"] == "cleaned":
                raise OSError("fixture post-replace fsync failure")
        with patch.object(self.store, "save", side_effect=fail_after_replace):
            result = standard.apply(self.args, self.store)
        self.assertEqual(result["outcome"], "terminal_commit_unconfirmed")
        self.assertTrue(result["allocator_may_already_be_released"])
        self.assertTrue(result["fresh_inspection_required"])
        calls = self.observer.call_count
        result = standard.apply(self.args, self.store)
        self.assertEqual(result["outcome"], "reconciled")
        self.assertGreater(self.observer.call_count, calls)
        self.destroy.assert_called_once()

    def test_old_writer_reuse_session_boot_and_incomplete_procfs_refuse(self):
        for patcher in (
            patch.object(standard.processes, "members", return_value=[{"pid": 1}]),
            patch.object(standard.processes, "process", return_value={"pid": 987654, "start": "reused"}),
            patch.object(standard.processes, "boot_id", return_value=str(uuid.uuid4())),
            patch.object(standard.recovery_system, "complete_proc_view", side_effect=RunError("process_visibility_unproven")),
        ):
            with patcher:
                result = standard.inspect(self.args, self.store)
                self.assertFalse(result["eligible"])
        self.destroy.assert_not_called()

    def test_runtime_unsupported_or_unreadable_blocks_without_forensic_fallback(self):
        with patch.object(runtime, "qualify_current_runtime", side_effect=RunError("standard_profile_service_unsupported")):
            result = standard.inspect(self.args, self.store)
            self.assertEqual(result["blockers"], ["standard_profile_service_unsupported"])
        with patch.object(standard.source, "verify_source", side_effect=RunError("approved_producing_source_unavailable")):
            self.assertFalse(standard.inspect(self.args, self.store)["eligible"])
        self.spawn.assert_not_called()

    def test_completed_or_pending_attempt_cannot_rewrite_original_history(self):
        self.approve_fixture_plan()
        standard.apply(self.args, self.store)
        final = self.store.load(self.data["id"])
        final["operations"][-1]["completion"] = self.operation
        self.store.save(final)
        self.assertFalse(standard.inspect(self.args, self.store)["eligible"])
        with self.assertRaises(RunError):
            standard.apply(self.args, self.store)

    def test_worker_resource_lock_substitution_and_timeout_fail_closed(self):
        path = self.store.directory(self.data["id"]) / ".resources.lock"
        with self.assertRaisesRegex(RunError, "lock_replaced"):
            with standard.worker_resource_lock(path):
                replacement = path.with_name("replacement.lock")
                replacement.touch(mode=0o600)
                replacement.replace(path)
        with patch.object(standard.time, "monotonic", side_effect=[0, 11]):
            with self.assertRaisesRegex(RunError, "lock_timeout"):
                with standard.worker_resource_lock(path):
                    self.fail("timeout must not enter body")

    def test_uncertain_mutation_retains_intent_and_explicit_retry_does_not_repeat_rpc(self):
        self.approve_fixture_plan()
        with patch.object(runtime, "destroy_exact_network", side_effect=RunError("standard_network_destroy_uncertain")) as mutation:
            with self.assertRaisesRegex(RunError, "destroy_uncertain"):
                standard.apply(self.args, self.store)
            final = self.store.load(self.data["id"])
            self.assertEqual(final["status"], "running")
            self.assertEqual(final[standard.KEY]["attempts"][-1]["phase"], "intent")
            with self.assertRaisesRegex(RunError, "operator_review"):
                standard.apply(self.args, self.store)
            mutation.assert_called_once()

    def test_cli_requires_explicit_profile_exclusive_modes_and_exact_acceptance(self):
        from isolated_runs import context
        common = [
            "recover-network-tail", "--backend", "kvm", "--scenario", self.args.scenario,
            "--role", self.args.role, "--operation", self.operation,
        ]
        for extra in (
            ["--dry-run", "--apply"], ["--dry-run", "--profile", "unsupported"],
            ["--dry-run", "--profile", runtime.PROFILE, "--accept-profile", runtime.PROFILE],
            ["--apply", "--profile", runtime.PROFILE],
        ):
            with self.subTest(extra=extra), patch.object(context, "Store") as constructor, \
                    contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(context.main(common + extra), 1)
                constructor.assert_not_called()
        with patch.object(standard, "inspect", return_value={"eligible": False}) as inspect, \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(context.main(common + [
                "--dry-run", "--profile", runtime.PROFILE, "--producing-source-root", self.args.producing_source_root,
            ]), 0)
            inspect.assert_called_once()


class StandardNetworkObservationTests(unittest.TestCase):
    def setUp(self):
        self.fixture = network_tests.NetworkRemovalTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.present = True
        self.routes = {4: [], 6: []}
        self.addresses = []
        self.addCleanup(patch.stopall)
        patch.object(runtime, "read_query", side_effect=self.query).start()

    def query(self, argv, **kwargs):
        fixture = self.fixture
        if "net-list" in argv:
            ids = [node.findtext("uuid") for node in fixture.networks]
            if "--persistent" in argv or not self.present:
                ids = [identity for identity in ids if identity != fixture.intent["id"]]
            return "\n".join(ids)
        if argv == ["ip", "-j", "address", "show"]:
            import json
            return json.dumps(self.addresses)
        if "route" in argv:
            import json
            return json.dumps(self.routes[4 if "-4" in argv else 6])
        if argv == ["ip", "-j", "link", "show"] and not self.present:
            import json
            return json.dumps([{"ifname": "otherbr", "ifindex": 20}])
        return fixture.readonly(argv, **kwargs)

    def test_exact_transient_network_then_uuid_name_bridge_and_routes_absence(self):
        self.assertEqual(standard.observe_network(self.fixture.run)["network"], "present")
        self.present = False
        self.assertEqual(standard.observe_network(self.fixture.run, require_absent=True)["network"], "absent")

    def test_persistent_replaced_target_and_foreign_references_refuse(self):
        query = self.query
        with patch.object(runtime, "read_query", side_effect=lambda argv, **kwargs: (
            self.fixture.intent["id"] if "net-list" in argv and "--persistent" in argv else query(argv, **kwargs)
        )):
            with self.assertRaises(RunError):
                standard.observe_network(self.fixture.run)
        self.fixture.persistent[self.fixture.foreign_id] = self.fixture.domain("network", {"network": self.fixture.intent["name"]})
        with self.assertRaises(RunError):
            standard.observe_network(self.fixture.run)

    def test_only_foreign_bare_inactive_dangling_source_is_tolerated(self):
        self.fixture.persistent[self.fixture.foreign_id] = self.fixture.domain("network", {"network": "missing"})
        self.assertEqual(standard.observe_network(self.fixture.run)["network"], "present")
        self.fixture.active[self.fixture.foreign_id] = self.fixture.domain("user")
        with self.assertRaises(RunError):
            standard.observe_network(self.fixture.run)

    def test_parent_kernel_address_and_multipath_route_leftovers_refuse(self):
        self.present = False
        subnet = self.fixture.run["subnet"]
        import ipaddress
        address = str(ipaddress.ip_network(subnet)[1])
        self.addresses = [{"ifname": "otherbr", "ifindex": 20, "addr_info": [
            {"family": "inet", "local": address, "prefixlen": 24},
        ]}]
        with self.assertRaises(RunError):
            standard.observe_network(self.fixture.run, require_absent=True)
        self.addresses = []
        self.routes[4] = [{"dst": "default", "multipath": [{"gateway": address, "dev": "otherbr"}]}]
        with self.assertRaises(RunError):
            standard.observe_network(self.fixture.run, require_absent=True)

    def test_between_snapshot_churn_refuses(self):
        query, seen = self.query, [0]
        def changed(argv, **kwargs):
            if argv == ["ip", "-j", "address", "show"]:
                seen[0] += 1
                if seen[0] == 2:
                    return '[{"ifname":"other","ifindex":22,"addr_info":[]}]'
            return query(argv, **kwargs)
        with patch.object(runtime, "read_query", side_effect=changed), self.assertRaisesRegex(RunError, "snapshots_changed"):
            standard.observe_network(self.fixture.run)

    def ordinary_addresses(self):
        return [{
            "ifname": "otherbr", "ifindex": 20, "flags": ["BROADCAST", "UP"], "master": "unrelated",
            "addr_info": [{
                "family": "inet6", "local": "2001:db8::10", "prefixlen": 64,
                "scope": "global", "dynamic": True, "flags": ["temporary"],
                "valid_life_time": 5301, "preferred_life_time": 5301,
            }],
        }]

    def observe_address_pair(self, first, second, *, changed_fact=None):
        import json
        query, seen = self.query, [0]
        links = copy.deepcopy(self.fixture.links)
        def pair(argv, **kwargs):
            if argv == ["ip", "-j", "address", "show"]:
                seen[0] += 1
                return json.dumps(first if seen[0] == 1 else second)
            if changed_fact == "route" and "route" in argv and seen[0] == 2 and "-4" in argv:
                return '[{"dst":"203.0.113.0/24","dev":"otherbr"}]'
            if changed_fact == "link" and argv == ["ip", "-j", "link", "show"] and seen[0] == 1:
                self.fixture.links[1]["ifindex"] = 21
            return query(argv, **kwargs)
        try:
            with patch.object(runtime, "read_query", side_effect=pair):
                return standard.observe_network(self.fixture.run)
        finally:
            self.fixture.links = links

    def test_ordinary_address_lifetime_countdown_accepts_without_mutating_raw_observations(self):
        first = self.ordinary_addresses()
        second = copy.deepcopy(first)
        for key in ("valid_life_time", "preferred_life_time"):
            second[0]["addr_info"][0][key] -= 1
        original = copy.deepcopy((first, second))
        self.assertEqual(self.observe_address_pair(first, second)["network"], "present")
        self.assertEqual((first, second), original)
        self.assertEqual(first[0]["addr_info"][0]["preferred_life_time"], 5301)
        self.assertEqual(second[0]["addr_info"][0]["preferred_life_time"], 5300)

    def test_address_prefix_scope_flags_interface_master_and_inventory_changes_refuse(self):
        first = self.ordinary_addresses()
        cases = []
        for key, value in (
            ("local", "2001:db8::11"), ("prefixlen", 80), ("scope", "link"),
            ("flags", ["temporary", "deprecated"]), ("dynamic", False),
        ):
            changed = copy.deepcopy(first)
            changed[0]["addr_info"][0][key] = value
            cases.append(changed)
        for key, value in (
            ("ifname", "other-new"), ("ifindex", 21), ("flags", ["UP"]),
            ("master", "different"), ("altnames", ["new-alias"]),
        ):
            changed = copy.deepcopy(first)
            changed[0][key] = value
            cases.append(changed)
        cases.extend(([], first + [dict(first[0], ifname="extra", ifindex=30)]))
        for changed in cases:
            with self.subTest(changed=changed), self.assertRaisesRegex(RunError, "snapshots_changed"):
                self.observe_address_pair(first, changed)

    def test_lifetime_class_deprecation_renewal_and_unknown_fields_cannot_be_normalized_away(self):
        first = self.ordinary_addresses()
        for valid, preferred in ((4294967295, 4294967295), ("forever", "forever"), (5301, 0), (5302, 5301)):
            second = copy.deepcopy(first)
            second[0]["addr_info"][0].update(valid_life_time=valid, preferred_life_time=preferred)
            with self.subTest(valid=valid, preferred=preferred), self.assertRaises(RunError):
                self.observe_address_pair(first, second)
        first[0]["addr_info"][0]["preferred_life_time"] = 0
        second = copy.deepcopy(first)
        second[0]["addr_info"][0]["preferred_life_time"] = 1
        with self.assertRaisesRegex(RunError, "snapshots_changed"):
            self.observe_address_pair(first, second)
        second = copy.deepcopy(first)
        second[0]["addr_info"][0]["unrecognized_lifetime_ms"] = 5300000
        with self.assertRaisesRegex(RunError, "snapshots_changed"):
            self.observe_address_pair(first, second)

    def test_unsupported_lifetime_values_or_inconsistent_pairs_refuse_even_if_unchanged(self):
        for value in (-1, 4294967296, True, 5301.0, None, "5301", "infinite", {}, []):
            addresses = self.ordinary_addresses()
            addresses[0]["addr_info"][0]["valid_life_time"] = value
            with self.subTest(value=value), self.assertRaisesRegex(RunError, "lifetime_invalid"):
                self.observe_address_pair(addresses, addresses)
        for valid, preferred in ((10, 11), (10, "forever"), (0, 1)):
            addresses = self.ordinary_addresses()
            addresses[0]["addr_info"][0].update(valid_life_time=valid, preferred_life_time=preferred)
            with self.subTest(valid=valid, preferred=preferred), self.assertRaisesRegex(RunError, "lifetime_invalid"):
                self.observe_address_pair(addresses, addresses)
        addresses = self.ordinary_addresses()
        del addresses[0]["addr_info"][0]["preferred_life_time"]
        with self.assertRaisesRegex(RunError, "lifetime_invalid"):
            self.observe_address_pair(addresses, addresses)

    def test_forever_uint32_and_literal_are_equivalent_but_routes_and_links_still_compare(self):
        first = self.ordinary_addresses()
        second = copy.deepcopy(first)
        for key in ("valid_life_time", "preferred_life_time"):
            first[0]["addr_info"][0][key] = 4294967295
            second[0]["addr_info"][0][key] = "forever"
        self.assertEqual(self.observe_address_pair(first, second)["network"], "present")
        for fact in ("route", "link"):
            with self.subTest(fact=fact), self.assertRaisesRegex(RunError, "snapshots_changed"):
                self.observe_address_pair(first, second, changed_fact=fact)


class StandardMutationGrammarTests(unittest.TestCase):
    def test_only_exact_uuid_net_destroy_is_exposed_and_no_sudo_or_undefine(self):
        identity = str(uuid.uuid4())
        with patch.object(runtime, "_run") as command:
            runtime.destroy_exact_network(identity)
            command.assert_called_once_with(
                ["/usr/bin/virsh", "--connect", "qemu:///system", "net-destroy", identity], readonly=False,
            )
            for invalid in ("guest-name", identity.upper(), identity + " --undefine"):
                with self.subTest(invalid=invalid), self.assertRaises((RunError, ValueError)):
                    runtime.destroy_exact_network(invalid)
        with patch.object(runtime, "_run") as command:
            for argv in (
                ["virsh", "--connect", "qemu:///system", "net-destroy", identity],
                ["virsh", "--connect", "qemu:///other", "net-list", "--all", "--uuid"],
                ["sudo", "virsh", "net-destroy", identity],
                ["nft", "-j", "list", "ruleset"],
            ):
                with self.assertRaises((RunError, ValueError)):
                    runtime.read_query(argv)
            command.assert_not_called()


class StandardInstalledRuntimeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent)
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.paths = {}
        for index, name in enumerate((
            "/etc/os-release", runtime.DAEMON, runtime.DRIVER,
            runtime.UNIT, "/usr/bin/virsh", "/usr/sbin/ip", "/usr/bin/rpm", "/usr/bin/systemctl",
        )):
            path = self.root / str(index)
            path.write_text('ID=fedora\nVERSION_ID=44\n' if index == 0 else "fixture-bytes-" + str(index))
            self.paths[name] = path
        self.files = {
            name: hashlib.sha256(self.paths[name].read_bytes()).hexdigest() for name in (runtime.DAEMON, runtime.DRIVER, runtime.UNIT)
        }
        self.service = {
            "ActiveState": "active", "SubState": "running", "MainPID": "8888",
            "ExecStart": "{ path=" + runtime.DAEMON + " ; argv[]=" + runtime.DAEMON + " ; }",
            "PrivateNetwork": "no", "NetworkNamespacePath": "",
            "FragmentPath": runtime.UNIT, "DropInPaths": "",
            "TimeoutStopFailureMode": "terminate",
        }
        self.dropin = self.root / "reviewed-dropin"
        self.dropin.write_text(
            "# This file is part of the systemd package.\n"
            "# See https://fedoraproject.org/wiki/Changes/Shorter_Shutdown_Timer.\n"
            "#\n"
            "# To facilitate debugging when a service fails to stop cleanly,\n"
            '# TimeoutStopFailureMode=abort is set to "crash" services that fail to stop in\n'
            "# the time allotted. This will cause the service to be terminated with SIGABRT\n"
            "# and a coredump to be generated.\n"
            "#\n"
            "# To undo this configuration change, create a mask file:\n"
            "#   sudo mkdir -p /etc/systemd/system/service.d\n"
            "#   sudo ln -sv /dev/null /etc/systemd/system/service.d/10-timeout-abort.conf\n"
            "\n"
            "[Service]\n"
            "TimeoutStopFailureMode=abort\n",
        )
        self.dropin.chmod(0o644)
        self.dropin_package = f"systemd|{runtime.SYSTEMD_BUILD}|{runtime.SYSTEMD_SOURCE_RPM}|8"
        self.dropin_digest = runtime.DROPIN_SHA256
        self.queries = []
        self.addCleanup(patch.stopall)
        patch.object(runtime.recovery_commands, "root_path", side_effect=lambda path: (
            Path(runtime.DROPIN) if str(path) == runtime.DROPIN else self.paths[str(path)]
        )).start()
        patch.object(runtime, "_run", side_effect=self.query).start()
        patch.object(runtime.processes, "process", return_value={
            "pid": 8888, "start": "4", "uid": 0, "zombie": False,
        }).start()
        patch.object(runtime.processes, "boot_id", return_value=str(uuid.uuid4())).start()
        self.arguments = patch.object(runtime, "daemon_arguments", return_value=[runtime.DAEMON]).start()
        original_open, original_fstat, original_lstat = os.open, os.fstat, Path.lstat
        def root_stat(info):
            fields = {name: getattr(info, name) for name in (
                "st_dev", "st_ino", "st_mode", "st_uid", "st_nlink",
                "st_size", "st_mtime_ns", "st_ctime_ns",
            )}
            fields["st_uid"] = 0
            return SimpleNamespace(**fields)
        patch.object(runtime.os, "open", side_effect=lambda path, flags: original_open(
            self.dropin if str(path) == runtime.DROPIN else path, flags,
        )).start()
        patch.object(runtime.os, "fstat", side_effect=lambda fd: root_stat(original_fstat(fd))).start()
        patch.object(Path, "lstat", lambda path: (
            root_stat(original_lstat(self.dropin)) if str(path) == runtime.DROPIN else original_lstat(path)
        )).start()

    def query(self, argv, *, readonly):
        self.assertTrue(readonly)
        self.queries.append(argv)
        if argv[0] == "/usr/bin/rpm":
            if argv[1] == "-qf":
                self.assertEqual(argv[-1], runtime.DROPIN)
                return self.dropin_package if "%{NAME}" in argv[3] else runtime.DROPIN + "|" + self.dropin_digest
            if "%{NAME}" in argv[3]:
                return f"{runtime.PACKAGE}|{runtime.BUILD}|{runtime.SOURCE_RPM}|8"
            return "\n".join(path + "|" + digest for path, digest in self.files.items())
        if argv[0] == runtime.DAEMON:
            return "virtnetworkd (libvirt) 12.0.0"
        if argv[0] == "/usr/bin/systemctl":
            return "\n".join(key + "=" + value for key, value in self.service.items())
        self.fail("unexpected query")

    def test_installed_bytes_and_service_birth_measured_not_loaded_image_or_hooks(self):
        result = runtime.qualify_current_runtime()
        self.assertEqual(result["installed_files"], self.files)
        self.assertEqual(result["claims"]["loaded_image_attestation"], "unverified")
        self.assertEqual(result["claims"]["independent_helper_verification"], "unverified")
        self.assertFalse(any("sudo" in argument or "nft" in argument or "/proc" in argument for argv in self.queries for argument in argv))

    def test_changed_build_bytes_or_service_namespace_are_rejected(self):
        self.files[runtime.DRIVER] = "0" * 64
        with self.assertRaisesRegex(RunError, "installed_bytes_changed"):
            runtime.qualify_current_runtime()
        self.files[runtime.DRIVER] = hashlib.sha256(self.paths[runtime.DRIVER].read_bytes()).hexdigest()
        self.service["PrivateNetwork"] = "yes"
        with self.assertRaisesRegex(RunError, "service_unsupported"):
            runtime.qualify_current_runtime()

    def test_packaged_systemd_variable_uses_measured_actual_argv_not_variable_expansion(self):
        self.service["ExecStart"] = (
            "{path=" + runtime.DAEMON + ";argv[]=" + runtime.DAEMON
            + " $VIRTNETWORKD_ARGS;ignore_errors=no;}"
        )
        for arguments in (
            [runtime.DAEMON], [runtime.DAEMON, "--timeout", "120"], [runtime.DAEMON, "--timeout=120"],
        ):
            self.arguments.return_value = arguments
            with self.subTest(arguments=arguments):
                result = runtime.qualify_current_runtime()
                self.assertEqual(result["daemon_arguments"], arguments)
                self.arguments.assert_called_with(8888, {
                    "pid": 8888, "start": "4", "uid": 0, "zombie": False,
                })
        self.arguments.side_effect = RunError("standard_profile_daemon_arguments_unproven")
        with self.assertRaisesRegex(RunError, "arguments_unproven"):
            runtime.qualify_current_runtime()

    def test_unknown_variable_options_fragment_dropins_or_literal_conflict_refuse(self):
        original = copy.deepcopy(self.service)
        for field, value in (
            ("ExecStart", "{ path=" + runtime.DAEMON + " ; argv[]=" + runtime.DAEMON + " $OTHER_ARGS ; }"),
            ("ExecStart", "{ path=" + runtime.DAEMON + " ; argv[]=" + runtime.DAEMON + " $VIRTNETWORKD_ARGS --listen ; }"),
            ("ExecStart", "{ path=" + runtime.DAEMON + " ; argv[]=" + runtime.DAEMON + " ${VIRTNETWORKD_ARGS} ; }"),
            ("FragmentPath", "/unreviewed/virtnetworkd.service"),
            ("DropInPaths", "/etc/systemd/system/virtnetworkd.service.d/override.conf"),
        ):
            self.service = dict(original, **{field: value})
            with self.subTest(field=field, value=value), self.assertRaisesRegex(RunError, "service_unsupported"):
                runtime.qualify_current_runtime()
        self.service = original
        self.arguments.return_value = [runtime.DAEMON, "--timeout", "120"]
        with self.assertRaisesRegex(RunError, "arguments_conflicting"):
            runtime.qualify_current_runtime()

    def test_reviewed_fedora_global_timeout_abort_dropin_is_authenticated_and_bound(self):
        self.assertEqual(self.dropin.stat().st_size, runtime.DROPIN_BYTES)
        self.assertEqual(hashlib.sha256(self.dropin.read_bytes()).hexdigest(), runtime.DROPIN_SHA256)
        self.service["DropInPaths"] = runtime.DROPIN
        self.service["TimeoutStopFailureMode"] = "abort"
        result = runtime.qualify_current_runtime()
        self.assertEqual(result["distribution_dropin"], {
            "paths": [runtime.DROPIN], "package": "systemd", "build": runtime.SYSTEMD_BUILD,
            "source_rpm": runtime.SYSTEMD_SOURCE_RPM, "sha256": runtime.DROPIN_SHA256,
            "bytes": runtime.DROPIN_BYTES, "effective_timeout_stop_failure_mode": "abort",
        })
        self.assertTrue(any(argv[1] == "-qf" for argv in self.queries if argv[0] == "/usr/bin/rpm"))

    def test_unknown_additional_changed_effective_or_altered_dropin_refuses(self):
        self.service.update(DropInPaths=runtime.DROPIN, TimeoutStopFailureMode="abort")
        for value in (
            runtime.DROPIN + " /etc/systemd/system/service.d/extra.conf",
            runtime.DROPIN + " " + runtime.DROPIN,
            "/usr/lib/systemd/system/service.d/other.conf",
        ):
            self.service["DropInPaths"] = value
            with self.subTest(value=value), self.assertRaisesRegex(RunError, "service_unsupported"):
                runtime.qualify_current_runtime()
        self.service["DropInPaths"] = runtime.DROPIN
        self.service["TimeoutStopFailureMode"] = "terminate"
        with self.assertRaisesRegex(RunError, "service_unsupported"):
            runtime.qualify_current_runtime()
        self.service["TimeoutStopFailureMode"] = "abort"
        self.dropin_package = "foreign-package|259.8-1.fc44|foreign.src.rpm|8"
        with self.assertRaisesRegex(RunError, "dropin_package_unsupported"):
            runtime.qualify_current_runtime()
        self.dropin_package = f"systemd|{runtime.SYSTEMD_BUILD}|{runtime.SYSTEMD_SOURCE_RPM}|8"
        self.dropin_digest = "0" * 64
        with self.assertRaisesRegex(RunError, "package_digest_changed"):
            runtime.qualify_current_runtime()
        self.dropin_digest = runtime.DROPIN_SHA256
        original = self.dropin.read_bytes()
        self.dropin.write_bytes(original.replace(b"=abort", b"=other"))
        with self.assertRaisesRegex(RunError, "dropin_bytes_changed"):
            runtime.qualify_current_runtime()
        self.dropin.write_bytes(original)
        self.dropin.chmod(0o666)
        with self.assertRaisesRegex(RunError, "dropin_file_untrusted"):
            runtime.qualify_current_runtime()
        self.dropin.chmod(0o644)
        with patch.object(runtime.os, "open", side_effect=PermissionError):
            with self.assertRaises(PermissionError):
                runtime.qualify_current_runtime()


class StandardDaemonArgumentTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent)
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / "cmdline"
        self.identity = {"pid": 8888, "start": "4", "uid": 0, "zombie": False}
        self.path.write_bytes(runtime.DAEMON.encode() + b"\0")
        self.open = os.open
        self.fstat = os.fstat
        self.addCleanup(patch.stopall)
        self.process = patch.object(runtime.processes, "process", return_value=self.identity).start()
        self.pin = patch.object(runtime.os, "pidfd_open", side_effect=lambda pid: self.open(self.path, os.O_RDONLY)).start()
        patch.object(runtime.os, "open", side_effect=self.open_cmdline).start()
        patch.object(runtime.os, "fstat", side_effect=self.root_owned_stat).start()

    def open_cmdline(self, name, flags):
        self.assertEqual(name, "/proc/8888/cmdline")
        self.assertTrue(flags & os.O_NOFOLLOW)
        self.assertTrue(flags & os.O_NONBLOCK)
        return self.open(self.path, os.O_RDONLY)

    def root_owned_stat(self, fd):
        info = list(self.fstat(fd))
        info[4] = 0
        return os.stat_result(info)

    def test_only_reviewed_actual_arguments_are_accepted_and_pid_is_pinned(self):
        for arguments in (
            [runtime.DAEMON], [runtime.DAEMON, "--timeout", "120"], [runtime.DAEMON, "--timeout=120"],
        ):
            self.path.write_bytes(b"\0".join(item.encode() for item in arguments) + b"\0")
            with self.subTest(arguments=arguments):
                self.assertEqual(runtime.daemon_arguments(8888, self.identity), arguments)
                self.pin.assert_called_with(8888)

    def test_unexpected_expansion_truncation_size_and_permission_fail_closed(self):
        for content in (
            b"", runtime.DAEMON.encode(), b"x" * 4097,
            runtime.DAEMON.encode() + b"\0--config\0/unreviewed\0",
            runtime.DAEMON.encode() + b"\0$VIRTNETWORKD_ARGS\0",
            runtime.DAEMON.encode() + b"\0--timeout\0" + b"121\0",
        ):
            self.path.write_bytes(content)
            with self.subTest(content=content[:30]), self.assertRaises(RunError):
                runtime.daemon_arguments(8888, self.identity)
        with patch.object(runtime.os, "open", side_effect=PermissionError), self.assertRaisesRegex(RunError, "arguments_unproven"):
            runtime.daemon_arguments(8888, self.identity)

    def test_birth_change_before_or_after_read_is_rejected(self):
        changed = dict(self.identity, start="5")
        for values in ([changed], [self.identity, changed]):
            self.process.side_effect = values
            with self.subTest(values=len(values)), self.assertRaisesRegex(RunError, "birth_changed"):
                runtime.daemon_arguments(8888, self.identity)


if __name__ == "__main__":
    unittest.main()
