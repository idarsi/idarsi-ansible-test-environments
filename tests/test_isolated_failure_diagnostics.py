"""Mocked failure diagnostics contracts: no guests, signals or backend commands."""

from contextlib import ExitStack
from copy import deepcopy
import datetime
import io
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from isolated_runs import admission, cli, diagnostics as d, diagnostics_guest as g
from isolated_runs.state import RunError, Store


class DiagnosticTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="diagnostics-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.store = Store(self.root / "state")
        self.data = self.store.allocate("podman", {}, lambda: [], self.root, "fixture")
        self.run_id = self.data["id"]
        self.original = {"pid": 12345, "start": "1", "boot": "fixture"}
        self.data.update(
            mode="supervised", status="running", mutation_protocol="sealed-v1",
            admission_protocol=admission.PROTOCOL, operations=[], workers=[self.original],
            guests=[{"logical": "one", "name": "owned-one", "id": "a" * 64}],
            instances_ready=[{"instance": "one"}],
            failure_diagnostics={"profile": d.PROFILE, "profile_digest": d.DIGEST,
                                 "state": "requested", "started_at": d.now(), "source": {}},
        )
        self.store.save(self.data)
        admission.initialize(self.store, self.run_id)

    def test_collection_is_between_original_settlement_and_owned_cleanup(self):
        events = []

        def drained(store, run_id):
            events.append("drain")
            admission.close(store, run_id)
            return store.load(run_id)

        def stopped(data):
            events.append("settle-diagnostics" if len(data["workers"]) > 1 else "settle-original")

        def spawn(store, data, argv, env, cwd, operation):
            self.assertEqual("closed", admission.gate(store, data["id"])["state"])
            self.assertEqual("settle-original", events[-1])
            self.assertNotIn("--scenario-name", argv)
            operation["worker"] = {"pid": 12346, "start": "2", "boot": "fixture"}
            data["workers"].append(operation["worker"])
            store.save(data)
            events.append("diagnostics")
            return SimpleNamespace(poll=lambda: 0, wait=lambda: 0, returncode=0)

        # The final instance inventory may already have been emptied by Molecule.
        from isolated_runs.state import atomic_json
        atomic_json(self.store.ephemeral(self.run_id) / "instance_config.yml", [])
        with patch("isolated_runs.cooperative_stop.drain_mutations", side_effect=drained), patch(
            "isolated_runs.processes.stop_workers", side_effect=stopped
        ), patch("isolated_runs.processes.spawn", side_effect=spawn), patch("sys.stdout", io.StringIO()):
            d.collect_before_cleanup(self.store, self.run_id, 7, lambda: False)
        events.append("owned-delete")
        self.assertEqual(["drain", "settle-original", "diagnostics", "settle-diagnostics",
                          "owned-delete"], events)
        request = self.store.load(self.run_id)["failure_diagnostics"]
        self.assertEqual(7, request["original_exit"])
        self.assertEqual([{"logical_guest": "one", "backend_id": "a" * 64}], request["targets"])
        self.assertEqual([], self.store.load(self.run_id)["operations"])

    def test_success_cancel_disabled_and_no_create_never_spawn(self):
        for code, cancelled, ready, enabled in (
            (0, False, True, True), (1, True, True, True), (1, False, False, True),
            (1, False, True, False),
        ):
            data = deepcopy(self.data)
            if not ready:
                data.pop("instances_ready")
            if not enabled:
                data.pop("failure_diagnostics")
            self.store.save(data)
            with patch("isolated_runs.cooperative_stop.drain_mutations",
                       return_value=data), patch("isolated_runs.processes.stop_workers"), patch(
                "isolated_runs.processes.spawn"
            ) as spawn:
                d.collect_before_cleanup(self.store, self.run_id, code, lambda: cancelled)
            spawn.assert_not_called()

    def test_unknown_original_settlement_cannot_authorize_diagnostic_worker(self):
        with patch("isolated_runs.cooperative_stop.drain_mutations", return_value=self.data), patch(
            "isolated_runs.processes.stop_workers", side_effect=RunError("uncertain")
        ), patch("isolated_runs.processes.spawn") as spawn:
            with self.assertRaises(RunError):
                d.collect_before_cleanup(self.store, self.run_id, 1, lambda: False)
        spawn.assert_not_called()

    def test_cancel_after_acceptance_settles_worker(self):
        child = Mock()
        child.poll.return_value = None
        with patch("isolated_runs.cooperative_stop.drain_mutations", return_value=self.data), patch(
            "isolated_runs.processes.stop_workers"
        ) as stopped, patch("isolated_runs.processes.spawn", return_value=child), patch(
            "sys.stdout", io.StringIO()
        ):
            d.collect_before_cleanup(self.store, self.run_id, 1, Mock(side_effect=[False, False, True]))
        self.assertEqual(2, stopped.call_count)
        child.wait.assert_called_once()

    def test_original_exit_and_cleanup_survive_diagnostics_or_persistence_failure(self):
        args = SimpleNamespace(role=str(self.root), scenario="fixture", backend="podman",
                               failure_diagnostics=True)
        for diagnostic_failure in (RunError("unavailable"), OSError("disk full"),
                                   RuntimeError("unexpected diagnostic failure")):
            data = self.store.load(self.run_id)
            data["status"] = "allocated"
            self.store.save(data)
            child = SimpleNamespace(poll=lambda: 17, returncode=17, wait=lambda: 17)
            with ExitStack() as stack:
                stack.enter_context(patch.object(cli.shutil, "which", return_value="/mock/tool"))
                stack.enter_context(patch.object(cli, "managed_environment", return_value={}))
                stack.enter_context(patch.object(cli, "parse_configuration",
                                                return_value={"platforms": [{"name": "one"}]}))
                stack.enter_context(patch.object(cli, "validate_platforms", side_effect=lambda _, p, s: p))
                stack.enter_context(patch.object(cli, "podman_context", return_value={}))
                stack.enter_context(patch.object(self.store, "allocate", return_value=data))
                stack.enter_context(patch.object(cli.signal, "signal", return_value=None))
                stack.enter_context(patch.object(cli, "spawn", return_value=child))
                stack.enter_context(patch.object(admission, "initialize"))
                stack.enter_context(patch.object(d, "source_identity", return_value={}))
                stack.enter_context(patch.object(d, "collect_before_cleanup", side_effect=diagnostic_failure))
                cleanup = stack.enter_context(patch.object(cli, "cleanup_locked"))
                stack.enter_context(patch("sys.stdout", io.StringIO()))
                stack.enter_context(patch("sys.stderr", io.StringIO()))
                self.assertEqual(17, cli.run(args, self.store))
            cleanup.assert_called_once_with(self.store, self.run_id)

    def test_transport_is_exact_id_owned_local_podman_without_name_fallback(self):
        self.data["context"] = {
            "podman": {"uid": os.getuid(), "graph_root": "g", "run_root": "r",
                       "network_backend": "net"},
        }
        info = {"host": {"security": {"rootless": True}, "networkBackend": "net"},
                "store": {"graphRoot": "g", "runRoot": "r"}}
        inspect = [{"Id": "a" * 64, "Config": {"Labels": {d.LABEL: self.run_id}}}]
        with patch.dict(os.environ, {}, clear=True), patch.object(
            d, "query", side_effect=[json.dumps(info), json.dumps(inspect)]
        ) as query:
            argv = d.transport(self.data, self.data["guests"][0], {"instance": "one"}, 100)
        self.assertEqual(["podman", "--remote=false", "inspect", "a" * 64], query.call_args.args[0])
        self.assertEqual(["podman", "--remote=false", "exec", "-i", "a" * 64], argv[:5])
        self.assertNotIn("owned-one", argv)
        for identity in (None, "short", "one; touch /no"):
            guest = dict(self.data["guests"][0], id=identity)
            with self.assertRaises(RunError), patch.object(d, "query") as query:
                d.transport(self.data, guest, {"instance": "one"}, 100)
            query.assert_not_called()

    def test_wrong_podman_owner_rejected(self):
        info = {"host": {"security": {"rootless": True}, "networkBackend": "n"},
                "store": {"graphRoot": "g", "runRoot": "r"}}
        self.data["context"] = {"podman": {"uid": os.getuid(), "graph_root": "g",
                                         "run_root": "r", "network_backend": "n"}}
        with patch.dict(os.environ, {}, clear=True), patch.object(
            d, "query", side_effect=[json.dumps(info),
                                   json.dumps([{"Id": "a" * 64, "Config": {"Labels": {}}}])]
        ), self.assertRaises(RunError):
            d.transport(self.data, self.data["guests"][0], {"instance": "one"}, 100)

    def test_kvm_exact_uuid_and_provisioning_unverified_ssh_options(self):
        identity = str(uuid.uuid4())
        self.data.update(backend="kvm", context={"libvirt": "qemu:///system"},
                         config={"platforms": [{"name": "one", "ssh_user": "molecule"}]},
                         _directory=str(self.store.directory(self.run_id)))
        guest = {"logical": "one", "name": "owned-one", "id": identity}
        ready = d.kvm_instance(self.data["config"]["platforms"][0], self.data["subnet"], 0,
                               Path(self.data["_directory"]) / "kvm_ed25519")
        xml = f"<domain><uuid>{identity}</uuid><name>owned-one</name><description>idarsi-run:{self.run_id}</description></domain>"
        with patch.object(d, "query", return_value=xml) as query:
            argv = d.transport(self.data, guest, ready, 100)
        self.assertEqual(identity, query.call_args.args[0][-1])
        for option in ("ForwardAgent=no", "ForwardX11=no", "ControlMaster=no", "ControlPath=none",
                       "BatchMode=yes", "StrictHostKeyChecking=no", "UserKnownHostsFile=/dev/null"):
            self.assertIn(option, argv)
        self.assertEqual(d.REMOTE_COMMAND, argv[-1])
        self.assertNotIn(ready["address"], d.REMOTE_COMMAND)
        with patch.object(d, "query", return_value=xml.replace(self.run_id, "foreign")):
            with self.assertRaises(RunError):
                d.transport(self.data, guest, ready, 100)
        with patch.object(d, "query", return_value=xml), self.assertRaises(RunError):
            d.transport(self.data, guest, dict(ready, user="root;bad"), 100)

    def test_fixed_guest_collector_caps_and_allowlists(self):
        discovered = "evil.service;touch loaded failed failed\n" + "\n".join(
            f"unit{i}.service loaded failed failed" for i in range(8))
        calls = []

        def read(argv, deadline):
            calls.append(argv)
            text = discovered if "--failed" in argv else (
                "Id=unit0.service\nEnvironment=PASSWORD=secret\nExecStart=unsafe\nResult=exit-code"
                if "show" in argv else "safe journal"
            )
            return {"status": "ok", "text": text, "truncated": False,
                    "remote_completion": "observed"}

        with patch.object(g.shutil, "which", return_value="/mock/tool"), patch.object(
            g, "read_command", side_effect=read
        ):
            report = g.collect({"started_at": "2026-01-01T00:00:00+00:00", "remaining": 30})
        self.assertEqual(8, len(report["items"]))
        self.assertTrue(report["units_truncated"])
        self.assertNotIn("Environment", json.dumps(report))
        self.assertNotIn("ExecStart", json.dumps(report))
        self.assertNotIn("evil.service", json.dumps(report))
        for argv in calls:
            self.assertNotIn("status", argv)
            if argv[0] == "journalctl":
                self.assertIn("--boot=0", argv)
                self.assertIn("--lines=100", argv)
        with patch.object(g.shutil, "which", return_value=None):
            self.assertEqual("missing_guest_tool", g.collect({
                "started_at": "2026-01-01T00:00:00+00:00", "remaining": 30})["reason"])

    def test_journal_window_uses_validated_portable_epoch_arguments(self):
        end = datetime.datetime(2026, 1, 2, 1, 2, 3, 456789, tzinfo=datetime.timezone.utc)

        class Clock(datetime.datetime):
            @classmethod
            def now(cls, tz=None):
                return end

        for started_at in ("2026-01-01T00:00:00+00:00",
                           "2026-01-01T05:30:00.123456+05:30"):
            start = datetime.datetime.fromisoformat(started_at)
            receipt = {"status": "ok", "text": "one.service loaded failed failed",
                       "truncated": False, "remote_completion": "observed"}
            with patch.object(g.datetime, "datetime", Clock), patch.object(
                g.shutil, "which", return_value="/mock/tool"
            ), patch.object(g, "read_command", return_value=receipt) as read:
                g.collect({"started_at": started_at, "remaining": 30})
            journal = next(call.args[0] for call in read.call_args_list
                           if call.args[0][0] == "journalctl")
            self.assertIn(f"--since=@{start.timestamp():.6f}", journal)
            self.assertIn(f"--until=@{end.timestamp():.6f}", journal)
            for argument in journal:
                if argument.startswith(("--since=", "--until=")):
                    self.assertRegex(argument, r"^--(?:since|until)=@[0-9]+\.[0-9]{6}$")

    def test_guest_early_returns_do_not_claim_started_collection(self):
        for started_at in ("not-a-time", None, "2026-01-01T00:00:00",
                           "9999-01-01T00:00:00+00:00", "1969-01-01T00:00:00+00:00"):
            with patch.object(g, "read_command") as read:
                value = g.collect({"started_at": started_at, "remaining": 30})
            self.assertEqual("invalid_time_window", value["reason"])
            self.assertEqual("not_started", value["remote_completion"])
            read.assert_not_called()
        with patch.object(g.shutil, "which", return_value=None), patch.object(
            g, "read_command"
        ) as read:
            value = g.collect({"started_at": "2026-01-01T00:00:00+00:00", "remaining": 30})
        self.assertEqual("missing_guest_tool", value["reason"])
        self.assertEqual("not_started", value["remote_completion"])
        read.assert_not_called()

    def test_guest_errors_are_explicit_without_inventing_completion(self):
        for payload, failure, expected in (
            (b"{", None, "not_started"),
            (b'{"started_at":"2026-01-01T00:00:00+00:00","remaining":30}',
             OSError("private failure details"), "unknown"),
        ):
            output = io.StringIO()
            with patch.object(g.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(payload))), patch.object(
                g.sys, "stdout", output
            ), patch.object(g, "collect", side_effect=failure) as collect:
                g.main()
            value = json.loads(output.getvalue())
            self.assertEqual("guest_collection_failed", value["reason"])
            self.assertEqual(expected, value["remote_completion"])
            self.assertNotIn("private failure details", output.getvalue())
            if expected == "not_started":
                collect.assert_not_called()

    def test_guest_receipts_preserve_only_explicit_valid_completion_states(self):
        missing = object()
        for completion in ("observed", "unknown", "not_started", missing, None, [], {},
                           0, "", "invalid"):
            payload = {"status": "partial", "items": []}
            if completion is not missing:
                payload["remote_completion"] = completion
            value = d.evidence({"stdout": json.dumps(payload).encode()})
            expected = completion if completion in ("observed", "unknown", "not_started") else "unknown"
            self.assertEqual(expected, value["remote_completion"])

    def test_guest_timeout_wrapper_is_fixed_and_never_claims_remote_completion(self):
        process = Mock()
        process.poll.return_value = None
        process.wait.return_value = 124
        selector = Mock()
        selector.__enter__ = Mock(return_value=selector)
        selector.__exit__ = Mock(return_value=False)
        selector.get_map.return_value = {1: True}
        selector.select.return_value = [(SimpleNamespace(fileobj=process.stdout), None)]
        ticks = iter(index / 10 for index in range(1000))
        with patch.object(g.subprocess, "Popen", return_value=process) as popen, patch.object(
            g.selectors, "DefaultSelector", return_value=selector
        ), patch.object(g.os, "read", return_value=b"x" * 8192), patch.object(
            g.time, "monotonic", side_effect=lambda: next(ticks)
        ):
            response = g.read_command(["journalctl", "--unit=one.service"], 20)
        self.assertEqual(["timeout", "--signal=TERM", "--kill-after=2s", "5s"],
                         popen.call_args.args[0][:4])
        self.assertNotIn("shell", popen.call_args.kwargs)
        self.assertLessEqual(len(response["text"].encode()), 65536)
        self.assertEqual("unknown", response["remote_completion"])

    def test_redaction_and_strict_untrusted_guest_response(self):
        payload = {"status": "ok", "items": [{"unit": "one.service", "kind": "journal",
                    "text": "pass\x00word=private \x1b[31m token=hidden\n-----BEGIN RSA PRIVATE KEY-----\nkey\n-----END RSA PRIVATE KEY-----",
                    "status": "ok", "truncated": False}]}
        value = d.evidence({"stdout": json.dumps(payload).encode()})
        rendered = json.dumps(value)
        for secret in ("private", "hidden", "\\u001b", "\\u0000", "\\nkey"):
            self.assertNotIn(secret, rendered)
        payload["items"][0]["unit"] = "one.service;evil"
        with self.assertRaises(ValueError):
            d.evidence({"stdout": json.dumps(payload).encode()})

    def test_bounded_transport_hanging_and_output_cap_mocked(self):
        for output in (b"", b"x" * 8192):
            process = Mock()
            process.stdout = Mock()
            process.stderr = Mock()
            process.stdin = None
            process.poll.return_value = None
            process.wait.return_value = 0
            selector = Mock()
            selector.__enter__ = Mock(return_value=selector)
            selector.__exit__ = Mock(return_value=False)
            selector.get_map.return_value = {1: True}
            selector.select.return_value = [(SimpleNamespace(fileobj=process.stdout, data=0), None)]
            ticks = iter(index / 10 for index in range(1000))
            with patch.object(d.subprocess, "Popen", return_value=process) as popen, patch.object(
                d.selectors, "DefaultSelector", return_value=selector
            ), patch.object(d.os, "read", return_value=output), patch.object(
                d.time, "monotonic", side_effect=lambda: next(ticks)
            ):
                response = d.bounded(["ssh", "fixed"], 3, cap=10)
            self.assertLessEqual(len(response["stdout"]), 10)
            self.assertEqual("unknown", response["remote_completion"])
            process.terminate.assert_called_once()
            self.assertNotIn("shell", popen.call_args.kwargs)

    def test_multihost_worker_private_retained_report_ready_owned_only(self):
        identity = {"pid": os.getsid(0), "start": "synthetic", "boot": "test-boot"}
        data = deepcopy(self.data)
        data["workers"].append(identity)
        data["failure_diagnostics"].update(
            attempt="test-attempt", state="accepted", worker=identity, original_exit=23)
        data["guests"] += [
            {"logical": "two", "name": "owned-two", "id": "b" * 64},
            {"logical": "notready", "name": "owned-three", "id": "c" * 64},
        ]
        data["instances_ready"].append({"instance": "two"})
        self.store.save(data)
        admission.close(self.store, self.run_id)
        response = {"status": "ok", "remote_completion": "observed", "truncated": False,
                    "stdout": json.dumps({"status": "ok", "items": [
                        {"unit": "one.service", "kind": "journal", "status": "ok",
                         "text": "token=not-to-be-persisted\x00", "truncated": False},
                    ]}).encode()}
        with patch("isolated_runs.processes.boot_id", return_value="test-boot"), patch(
            "isolated_runs.processes.process", return_value={"start": "synthetic"}
        ), patch.object(d, "transport", return_value=["fixed-read-only"]) as transport, patch.object(
            d, "bounded", return_value=response
        ):
            d.worker(self.store, self.run_id, "test-attempt")
        self.assertEqual(2, transport.call_count)
        directory = self.store.directory(self.run_id) / "diagnostics"
        artifact = directory / (d.PROFILE + ".json")
        self.assertEqual(0o700, directory.stat().st_mode & 0o777)
        self.assertEqual(0o600, artifact.stat().st_mode & 0o777)
        raw = artifact.read_text()
        self.assertNotIn("not-to-be-persisted", raw)
        self.assertNotIn("\\u0000", raw)
        self.assertEqual(["one", "two"], [guest["logical_guest"] for guest in json.loads(raw)["guests"]])
        self.assertEqual(23, json.loads(raw)["original_exit"])
        self.assertEqual("closed", admission.gate(self.store, self.run_id)["state"])

    def test_worker_cannot_self_authorize_or_reopen_mutation_gate(self):
        with patch.object(d, "transport") as transport, self.assertRaises(RunError):
            d.worker(self.store, self.run_id, "unaccepted")
        transport.assert_not_called()
        self.assertEqual("open", admission.gate(self.store, self.run_id)["state"])

    def test_local_transport_exit_is_not_remote_completion_proof(self):
        identity = {"pid": os.getsid(0), "start": "synthetic", "boot": "test-boot"}
        data = deepcopy(self.data)
        data["workers"].append(identity)
        data["failure_diagnostics"].update(
            attempt="test-attempt", state="accepted", worker=identity, original_exit=23)
        self.store.save(data)
        admission.close(self.store, self.run_id)
        response = {"status": "partial", "remote_completion": "observed", "truncated": False,
                    "stdout": b"", "exit_code": 255}
        with patch("isolated_runs.processes.boot_id", return_value="test-boot"), patch(
            "isolated_runs.processes.process", return_value={"start": "synthetic"}
        ), patch.object(d, "transport", return_value=["fixed-read-only"]), patch.object(
            d, "bounded", return_value=response
        ):
            d.worker(self.store, self.run_id, "test-attempt")
        artifact = self.store.directory(self.run_id) / "diagnostics" / (d.PROFILE + ".json")
        item = json.loads(artifact.read_text())["guests"][0]
        self.assertEqual("unknown", item["remote_completion"])
        self.assertEqual("partial", item["status"])


if __name__ == "__main__":
    unittest.main()
