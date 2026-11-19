"""Backend-free direct lifecycle safety regressions."""

import contextlib
import io
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from isolated_runs import context
from isolated_runs import cli
from isolated_runs.cli import cleanup_locked
from isolated_runs.state import RunError, Store


class DirectContextTests(unittest.TestCase):
    def test_init_configuration_cannot_change_before_first_create(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = Store(Path(temporary) / "state")
            result = {
                "role": temporary, "scenario": "podman-test", "backend": "podman",
                "ephemeral_directory": temporary, "generation": None,
            }
            args = type("Args", (), {"action": "init", "backend": "podman", "scenario": "podman-test"})()
            original = {"platforms": [{"name": "original"}]}
            with patch.object(context, "podman_context", return_value={}), \
                    patch.object(context, "discover", return_value=[]):
                context.direct(args, store, result, original)
            args.action = "create"
            with patch.object(context, "stop_workers"), patch.object(context, "spawn") as spawn:
                with self.assertRaisesRegex(RunError, "Configuration changed"):
                    context.direct(args, store, result, {"platforms": [{"name": "changed"}]})
                spawn.assert_not_called()
            self.assertEqual(store.load(result["generation"])["config"], original)

    def test_unpublished_never_mutated_allocation_can_be_recovered(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = Store(Path(temporary) / "state")
            result = {
                "role": temporary, "scenario": "podman-test", "backend": "podman",
                "ephemeral_directory": temporary, "generation": None,
            }
            args = type("Args", (), {"action": "init", "backend": "podman", "scenario": "podman-test"})()
            with (
                patch.object(context, "podman_context", return_value={}),
                patch.object(context, "discover", return_value=[]),
                patch.object(context, "atomic_json", side_effect=OSError("publication interrupted")),
            ):
                with self.assertRaisesRegex(OSError, "publication interrupted"):
                    context.direct(args, store, result, {})
            run_id = store.runs()[0]["id"]
            path, identity = context.pointer_path(store, result)
            with patch.object(cli, "Backend") as backend:
                cli.cleanup(store, run_id)
                cli.cleanup(store, run_id)
                backend.assert_not_called()
            final = store.load(run_id)
            self.assertEqual(final["status"], "cleaned")
            self.assertEqual(final["operations"], [])
            self.assertEqual(final["workers"], [])
            self.assertFalse(path.exists())
            # Pending metadata alone never authorizes removal after publication.
            final["status"] = "running"
            store.save(final)
            context.atomic_json(path, {"identity": identity, "generation": run_id})
            with self.assertRaisesRegex(RunError, "published"):
                cli.cleanup(store, run_id)
            self.assertEqual(store.load(run_id)["status"], "running")
            path.unlink()
            final["operations"] = [{"id": "uncertain", "action": "create"}]
            store.save(final)
            with self.assertRaisesRegex(RunError, "never mutated"):
                cli.cleanup(store, run_id)
            self.assertEqual(store.load(run_id)["status"], "running")

    def test_completed_destroy_cannot_reuse_generation_for_create(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = Store(Path(temporary) / "state")
            result = {
                "role": temporary, "scenario": "podman-test", "backend": "podman",
                "ephemeral_directory": temporary, "generation": None,
            }
            path, identity = context.pointer_path(store, result)
            data = store.allocate("podman", {}, lambda: [], Path(temporary), "podman-test")
            worker = {"pid": 123}
            data.update(
                mode="direct", direct_identity=identity, status="destroyed", workers=[worker],
                operations=[{
                    "id": "finished", "completion": "finished", "action": "destroy", "worker": worker,
                }],
                instances_ready=[{"instance": "stale"}],
            )
            store.save(data)
            context.atomic_json(path, {"identity": identity, "generation": data["id"]})
            args = type("Args", (), {"action": "create"})()
            with patch.object(context, "stop_workers"), \
                    patch.object(context, "members", return_value=[]), \
                    patch.object(context, "spawn") as spawn:
                with self.assertRaisesRegex(RunError, "run destroy before a new create"):
                    context.direct(args, store, result, {})
                spawn.assert_not_called()

    def test_failed_mutation_never_gets_completion_seal(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = Store(Path(temporary) / "state")
            for action in ("create", "destroy"):
                data = store.allocate("podman", {}, lambda: [], Path(temporary), "podman-test")
                identity = {"pid": 123, "boot": "test", "start": "1"}
                data.update(
                    mode="direct", direct_context={}, config={"platforms": []},
                    operations=[{"id": "operation", "action": action, "worker": identity}],
                    workers=[identity],
                )
                store.save(data)
                with patch.object(context, "Backend") as backend, \
                        patch.object(context, "members", return_value=[{"session": os.getsid(0)}]):
                    backend.return_value.create.side_effect = RunError("uncertain backend request")
                    backend.return_value.destroy_guests.side_effect = RunError("uncertain backend request")
                    with self.assertRaisesRegex(RunError, "uncertain backend"):
                        context.worker(store, data["id"], "operation", action)
                final = store.load(data["id"])
                self.assertNotIn("completion", final["operations"][0])
                self.assertNotEqual(final["status"], "cleaned")

    def test_supervised_identity_and_session_binding(self):
        with tempfile.TemporaryDirectory() as temporary:
            role = Path(temporary)
            store = Store(role / "state")
            data = store.allocate("podman", {}, lambda: [], role, "podman-test")
            data.update(status="running", workers=[{"pid": 123}])
            store.save(data)
            config = {
                "_idarsi_effective_scenario": "podman-test",
                "_idarsi_effective_role": temporary,
                "_idarsi_effective_ephemeral": str(store.ephemeral(data["id"])),
                "driver": {"safe_files": [str(store.ephemeral(data["id"]) / "collections" / "*")]},
                "platforms": [],
                "ansible": {"env": {"IDARSI_MOLECULE_BACKEND": "podman"}},
            }
            args = type("Args", (), {
                "role": temporary, "scenario": "podman-test", "backend": "podman",
            })()
            with (
                patch.object(context, "parse_configuration", return_value=config),
                patch.object(context, "validate_platforms", return_value=[]),
                patch.object(context, "members", return_value=[{"session": os.getsid(0)}]),
                patch.dict(os.environ, {"IDARSI_RUN_ID": data["id"], "IDARSI_HANDOFF": "v1"}, clear=True),
            ):
                self.assertEqual(context.resolved(args, store)[0]["mode"], "supervised")
                for field, value in (
                    ("role", "/foreign"), ("scenario", "foreign"), ("backend", "kvm"),
                    ("status", "cleaned"), ("mode", "direct"),
                ):
                    store.save(dict(data, **{field: value}))
                    with self.assertRaisesRegex(RunError, "binding mismatch"):
                        context.resolved(args, store)
                store.save(data)
                with patch.object(context, "members", return_value=[]):
                    with self.assertRaisesRegex(RunError, "binding mismatch"):
                        context.resolved(args, store)

    def test_recovered_allocation_is_not_published_or_revived(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = Store(Path(temporary) / "state")
            allocate = store.allocate

            def recovered(*args, **kwargs):
                data = allocate(*args, **kwargs)
                data["status"] = "cleaned"
                store.save(data)
                return data

            result = {
                "role": temporary, "scenario": "podman-test", "backend": "podman",
                "ephemeral_directory": temporary, "generation": None,
            }
            args = type("Args", (), {"action": "init", "backend": "podman", "scenario": "podman-test"})()
            with (
                patch.object(store, "allocate", side_effect=recovered),
                patch.object(context, "podman_context", return_value={}),
                patch.object(context, "discover", return_value=[]),
            ):
                with self.assertRaisesRegex(RunError, "recovered before context publication"):
                    context.direct(args, store, result, {})
            path, _ = context.pointer_path(store, result)
            self.assertFalse(path.exists())
            self.assertEqual(store.runs()[0]["status"], "cleaned")

    def test_sealed_destroy_releases_only_after_worker_returns(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = Store(Path(temporary) / "state")
            ephemeral = Path(temporary) / "ephemeral"
            ephemeral.mkdir()
            result = {
                "role": temporary, "scenario": "podman-test", "backend": "podman",
                "ephemeral_directory": str(ephemeral), "generation": None,
            }
            args = type("Args", (), {"action": "init", "backend": "podman", "scenario": "podman-test"})()
            with patch.object(context, "discover", return_value=[]), \
                    patch.object(context, "podman_context", return_value={}):
                context.direct(args, store, result, {"platforms": []})
            run_id = result["generation"]

            def fake_spawn(store, data, argv, env, cwd, operation):
                identity = {"pid": 123, "boot": "test", "start": "1"}
                operation["worker"] = identity
                data["workers"].append(identity)
                store.save(data)

                class Child:
                    def wait(self):
                        self_outer.assertNotEqual(store.load(run_id)["status"], "cleaned")
                        with patch.object(context, "members", return_value=[{"session": os.getsid(0)}]):
                            context.worker(store, run_id, operation["id"], operation["action"])
                        self_outer.assertEqual(store.load(run_id)["status"], "destroyed")
                        return 0

                return Child()

            self_outer = self
            args.action = "destroy"
            with (
                patch.object(context, "spawn", side_effect=fake_spawn),
                patch.object(context, "stop_workers"),
                patch.object(context, "members", return_value=[]),
                patch.object(context, "Backend"),
                patch.dict(os.environ, {"MOLECULE_INSTANCE_CONFIG": str(ephemeral / "instance.yml")}),
            ):
                context.direct(args, store, result, {})
            final = store.load(run_id)
            self.assertEqual(final["status"], "cleaned")
            self.assertIsNone(result["generation"])
            self.assertEqual(final["operations"][0]["completion"], final["operations"][0]["id"])

    @unittest.skipUnless(importlib.util.find_spec("molecule"), "Activate existing pinned Molecule")
    def test_actual_config_preserves_real_ephemeral_for_capability(self):
        self.exercise_actual_configuration()

    @unittest.skipUnless(importlib.util.find_spec("molecule"), "Activate existing pinned Molecule")
    def test_actual_config_honors_custom_env_file(self):
        self.exercise_actual_configuration(custom=True)

    def exercise_actual_configuration(self, custom=False):
        with tempfile.TemporaryDirectory() as temporary:
            role = Path(temporary)
            source = role / "molecule" / "podman-test" / "molecule.yml"
            source.parent.mkdir(parents=True)
            source.write_text(
                (context.REPO / "examples/molecule-managed-podman/molecule.yml").read_text(),
            )
            store = Store(role / "state")
            ephemeral = role / "real-ephemeral"
            args = type("Args", (), {
                "role": temporary, "backend": "podman", "scenario": "podman-test",
            })()
            environment = {
                "PATH": str(Path(sys.executable).parent) + os.pathsep + os.environ["PATH"],
                "HOME": temporary, "XDG_CACHE_HOME": str(role / "cache"),
                "IDARSI_TEST_ENVIRONMENT": str(context.REPO),
                "MOLECULE_EPHEMERAL_DIRECTORY": str(ephemeral),
            }
            if custom:
                source.write_text(source.read_text().replace(
                    "localhost/ansible-rocky10:latest", "${CONTEXT_TEST_IMAGE}",
                ))
                (role / ".env.yml").write_text("CONTEXT_TEST_IMAGE: localhost/wrong-default:latest\n")
                custom_file = role / "selected-env.yml"
                custom_file.write_text("CONTEXT_TEST_IMAGE: localhost/selected:latest\n")
                environment["MOLECULE_ENV_FILE"] = str(custom_file)
            with patch.dict(os.environ, environment, clear=True):
                result, config = context.resolved(args, store)
                # Use REAL Config.env, including its cached MOLECULE_FILE binding.
                with patch.dict(os.environ, config["_idarsi_effective_env"]):
                    bound, rebound_config = context.resolved(args, store)
                    self.assertEqual(config, rebound_config)
                    context.mapping(bound, [])
                if custom:
                    self.assertEqual(config["platforms"][0]["image"], "localhost/selected:latest")
            self.assertEqual(result["ephemeral_directory"], str(ephemeral))
            self.assertEqual(result["collections_directory"], str(ephemeral / "collections"))
            self.assertTrue(result["effective_config_validated"])
            self.assertEqual(config["_idarsi_effective_role"], temporary)
            self.assertEqual(store.runs(), [])
            data = store.allocate("podman", {}, lambda: [], role, "podman-test")
            data.update(status="running", workers=[{"pid": os.getsid(0)}])
            store.save(data)
            environment.update(
                MOLECULE_EPHEMERAL_DIRECTORY=str(store.ephemeral(data["id"])),
                IDARSI_RUN_ID=data["id"], IDARSI_HANDOFF="v1",
            )
            effective = cli.parse_configuration(role, "podman-test", environment, direct=True)
            environment.update(effective["_idarsi_effective_env"])
            with patch.dict(os.environ, environment, clear=True), \
                    patch.object(context, "members", return_value=[{"session": os.getsid(0)}]), \
                    patch.object(cli, "Backend"):
                self.assertEqual(context.resolved(args, store)[0]["mode"], "supervised")
                cli.lifecycle(store, "destroy", data["id"])

    def test_supervised_inspect_includes_manifest_as_single_json_object(self):
        result = {"mode": "supervised", "generation": "generation"}
        output = io.StringIO()
        with (
            patch.object(context, "Store") as store_class,
            patch.object(context, "resolved", return_value=(result, {})),
            contextlib.redirect_stdout(output),
        ):
            store_class.return_value.load.return_value = {"subnet": "10.0.0.0/24"}
            self.assertEqual(context.main([
                "inspect", "--backend", "podman", "--scenario", "podman-test",
            ]), 0)
            self.assertEqual(json.loads(output.getvalue())["manifest"]["subnet"], "10.0.0.0/24")

    def test_initial_destroy_preserves_collections_and_allocates_nothing(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = Store(Path(temporary) / "state")
            ephemeral = Path(temporary) / "ephemeral"
            collections = ephemeral / "collections"
            collections.mkdir(parents=True)
            sentinel = collections / "installed"
            sentinel.write_text("preserve")
            result = {
                "role": temporary, "scenario": "podman-test", "backend": "podman",
                "ephemeral_directory": str(ephemeral), "generation": None,
            }
            args = type("Args", (), {"action": "destroy"})()
            with patch.dict(os.environ, {"MOLECULE_INSTANCE_CONFIG": str(ephemeral / "instance.yml")}):
                context.direct(args, store, result, {})
            self.assertEqual(sentinel.read_text(), "preserve")
            self.assertEqual(store.runs(), [])

    def test_inspection_and_capabilities_never_query_or_create_backend(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = Store(Path(temporary) / "state")
            result = {
                "role": temporary, "scenario": "podman-test", "backend": "podman",
                "ephemeral_directory": temporary, "generation": None,
            }
            with patch.object(context, "Backend") as backend, \
                    patch.object(context, "discover") as discovery, \
                    patch.object(context, "podman_context") as podman:
                for action in ("capabilities", "resolve", "inspect"):
                    args = type("Args", (), {"action": action})()
                    self.assertIsNone(context.direct(args, store, result, {})["generation"])
                backend.assert_not_called()
                discovery.assert_not_called()
                podman.assert_not_called()
            self.assertEqual(store.runs(), [])

    def test_incomplete_destroy_retains_generation_and_deletes_nothing(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = Store(Path(temporary) / "state")
            result = {
                "role": temporary, "scenario": "podman-test", "backend": "podman",
                "ephemeral_directory": temporary, "generation": None,
            }
            path, identity = context.pointer_path(store, result)
            data = store.allocate("podman", {}, lambda: [], Path(temporary), "podman-test")
            data.update(
                mode="direct", direct_identity=identity,
                operations=[{"id": "uncertain", "action": "destroy"}],
            )
            store.save(data)
            context.atomic_json(path, {"identity": identity, "generation": data["id"]})
            with patch.object(context, "stop_workers"), patch.object(context, "Backend") as backend:
                args = type("Args", (), {"action": "destroy"})()
                with self.assertRaisesRegex(RunError, "inspection-only"):
                    context.direct(args, store, result, {})
                backend.assert_not_called()
            self.assertNotEqual(store.load(data["id"])["status"], "cleaned")

    def test_incomplete_operation_blocks_even_when_session_empty(self):
        data = {"operations": [{"id": "operation", "action": "create"}], "workers": []}
        with self.assertRaisesRegex(RunError, "inspection-only"):
            context.require_completed(data)

    def test_sealed_operation_requires_empty_session(self):
        data = {
            "operations": [{
                "id": "operation", "action": "create", "completion": "operation",
                "worker": {"pid": 1},
            }],
            "workers": [{"pid": 1}],
        }
        with patch.object(context, "members", return_value=[{"pid": 2}]):
            with self.assertRaisesRegex(RunError, "not empty"):
                context.require_completed(data)
        with patch.object(context, "members", return_value=[]):
            context.require_completed(data)

    def test_generic_cleanup_never_mutates_direct_generation(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = Store(Path(temporary) / "state")
            data = store.allocate("podman", {}, lambda: [], Path(temporary), "podman-test")
            data.update(mode="direct", operations=[{"id": "uncertain"}])
            store.save(data)
            with patch("isolated_runs.cli.Backend") as backend:
                with self.assertRaisesRegex(RunError, "inspection"):
                    cleanup_locked(store, data["id"])
                backend.assert_not_called()
            self.assertNotEqual(store.load(data["id"])["status"], "cleaned")

    def test_cleaned_generation_is_never_revived(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = Store(Path(temporary) / "state")
            result = {
                "role": temporary, "scenario": "podman-test", "backend": "podman",
                "ephemeral_directory": temporary, "generation": None,
            }
            path, identity = context.pointer_path(store, result)
            data = store.allocate("podman", {}, lambda: [], Path(temporary), "podman-test")
            data.update(mode="direct", direct_identity=identity, status="cleaned")
            store.save(data)
            path.write_text(json.dumps({"identity": identity, "generation": data["id"]}))
            path.chmod(0o600)
            args = type("Args", (), {"action": "resolve"})()
            self.assertIsNone(context.direct(args, store, result, {})["generation"])

    def test_partial_handoff_fails_closed_and_environment_alone_does_not(self):
        with tempfile.TemporaryDirectory() as temporary:
            role = Path(temporary)
            args = type("Args", (), {
                "role": temporary, "scenario": "podman-test", "backend": "podman",
            })()
            config = {
                "_idarsi_effective_scenario": "podman-test",
                "_idarsi_effective_role": temporary,
                "_idarsi_effective_ephemeral": str(role / "ephemeral"),
                "driver": {"safe_files": [str(role / "ephemeral" / "collections" / "*")]},
                "platforms": [],
                "provisioner": {"env": {"IDARSI_MOLECULE_BACKEND": "podman"}},
            }
            store = Store(role / "state")
            with (
                patch.object(context, "parse_configuration", return_value=config),
                patch.object(context, "validate_platforms", return_value=[]),
                patch.dict(os.environ, {"IDARSI_TEST_ENVIRONMENT": temporary}, clear=True),
            ):
                self.assertEqual(context.resolved(args, store)[0]["mode"], "direct")
                for marker in ("IDARSI_RUN_ID", "IDARSI_HANDOFF", "IDARSI_HANDOFF_UNKNOWN"):
                    with patch.dict(os.environ, {marker: ""}):
                        with self.assertRaisesRegex(RunError, "Partial"):
                            context.resolved(args, store)


if __name__ == "__main__":
    unittest.main()
