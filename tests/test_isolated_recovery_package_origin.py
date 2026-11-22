"""Same-prefix package alias fixtures; never inspect an actual controller/host."""

import copy
import os
from pathlib import Path
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import test_isolated_recovery as fixtures
import test_isolated_recovery_review as context_fixtures
from isolated_runs import recovery
from isolated_runs.state import RunError


class PackageOriginAliasTests(unittest.TestCase):
    def setUp(self):
        self.fixture = context_fixtures.ExecutingContextTests(methodName="runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.prefix = self.fixture.prefix
        self.site = self.fixture.site
        self.alias = self.prefix / "lib64"
        self.alias.symlink_to("lib")
        self.alias_site = self.alias / "python3.12/site-packages"
        real_lstat = Path.lstat

        def metadata(path, *args, **kwargs):
            # Only external ancestors are synthetic trusted roots. All prefix,
            # lib/lib64, site, source and interpreter entries are real temp files.
            if path in self.fixture.root.parents:
                return SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o755)
            return real_lstat(path, *args, **kwargs)

        patch.object(Path, "lstat", metadata).start()
        patch.object(recovery, "trusted_path", wraps=context_fixtures.REAL_TRUSTED_PATH).start()

    def origin(self):
        return recovery.package_origin(self.alias_site, self.prefix, (3, 12))

    def test_realistic_lib64_distribution_origins_are_canonical_and_stable(self):
        plain = recovery.executing_context()
        self.fixture.site = self.alias_site
        aliased = recovery.executing_context()
        self.assertEqual(plain, aliased)
        self.assertEqual(aliased["package_origins"], {
            "ansible-core": str(self.site), "molecule": str(self.site),
        })
        self.assertEqual(self.origin(), self.site)
        self.assertEqual(os.readlink(self.alias), "lib")

    def test_general_trusted_path_still_rejects_this_alias(self):
        with self.assertRaisesRegex(RunError, "original_context_path_changed"):
            recovery.trusted_path(self.alias_site)

    def test_only_exact_relative_lib_target_is_supported(self):
        for target in (
            "./lib", "lib/../lib", "../sibling/lib", str(self.prefix / "lib"),
            "/tmp/foreign-lib", "lib64", "otherlib",
        ):
            self.alias.unlink()
            self.alias.symlink_to(target)
            with self.subTest(target=target), self.assertRaises(RunError):
                self.origin()

    def test_untrusted_alias_owner_rejected_without_relaxing_symlink_permissions(self):
        real_lstat = Path.lstat

        def metadata(path, *args, **kwargs):
            info = real_lstat(path, *args, **kwargs)
            if path == self.alias:
                return SimpleNamespace(
                    st_uid=os.getuid() + 10000, st_mode=info.st_mode,
                    st_dev=info.st_dev, st_ino=info.st_ino,
                    st_mtime_ns=info.st_mtime_ns, st_ctime_ns=info.st_ctime_ns,
                )
            return info

        with patch.object(Path, "lstat", metadata), self.assertRaisesRegex(RunError, "approved_controller_tooling_unproven"):
            self.origin()

    def test_target_and_ancestry_permissions_remain_strict(self):
        for path in (self.prefix, self.prefix / "lib", self.site):
            previous = stat.S_IMODE(path.stat().st_mode)
            path.chmod(0o775)
            try:
                with self.subTest(path=path.name), self.assertRaisesRegex(RunError, "untrusted_controller_path"):
                    self.origin()
            finally:
                path.chmod(previous)

    def test_nested_or_replaced_target_links_rejected(self):
        lib = self.prefix / "lib"
        real_lib = self.prefix / "otherlib"
        lib.rename(real_lib)
        lib.symlink_to("otherlib")
        with self.assertRaisesRegex(RunError, "original_context_path_changed"):
            self.origin()
        lib.unlink()
        real_lib.rename(lib)
        destination = self.prefix / "other-site"
        self.site.rename(destination)
        self.site.symlink_to(destination)
        with self.assertRaisesRegex(RunError, "original_context_path_changed"):
            self.origin()

    def test_foreign_sibling_traversal_and_file_origins_rejected(self):
        for location in (
            self.prefix.parent / "ansible-current-foreign/lib64/python3.12/site-packages",
            self.prefix / "lib64/other/site-packages",
            self.prefix / "lib64/python3.12/site-packages/..",
            Path("/foreign/PYTHONPATH/site-packages"),
        ):
            with self.subTest(location=location), self.assertRaises(RunError):
                recovery.package_origin(location, self.prefix, (3, 12))
        self.site.rmdir()
        self.site.write_text("fixture file, not a package directory\n")
        os.link(self.site, self.fixture.root / "file-origin-hardlink")
        with self.assertRaisesRegex(RunError, "approved_controller_tooling_unproven"):
            self.origin()

    def test_alias_substitution_during_measurement_rejected(self):
        real_lstat = Path.lstat
        count = [0]

        def metadata(path, *args, **kwargs):
            info = real_lstat(path, *args, **kwargs)
            if path == self.alias:
                count[0] += 1
                return SimpleNamespace(
                    st_uid=info.st_uid, st_mode=info.st_mode,
                    st_dev=info.st_dev, st_ino=info.st_ino + (count[0] > 1),
                    st_mtime_ns=info.st_mtime_ns, st_ctime_ns=info.st_ctime_ns,
                )
            return info

        with patch.object(Path, "lstat", metadata), self.assertRaisesRegex(RunError, "approved_controller_tooling_unproven"):
            self.origin()

    def test_canonical_origin_measurement_revalidates_receipt_after_fake_boot(self):
        plain = recovery.executing_context()
        self.fixture.site = self.alias_site
        aliased = recovery.executing_context()
        self.assertEqual(plain, aliased)
        run = fixtures.RecoveryTests(methodName="runTest")
        run.setUp()
        self.addCleanup(run.doCleanups)
        original_config = copy.deepcopy(run.data["config"])
        with patch.object(recovery, "trusted_context", return_value={
            "mode": "legacy_runtime_measured", "missing": ["IDARSI_TEST_ENVIRONMENT", "VIRTUAL_ENV"],
            "current": plain,
        }):
            run.prepare()
        run.boot.return_value = fixtures.NEW_BOOT
        with patch.object(recovery, "trusted_context", return_value={
            "mode": "legacy_runtime_measured", "missing": ["IDARSI_TEST_ENVIRONMENT", "VIRTUAL_ENV"],
            "current": aliased,
        }):
            self.assertEqual(run.apply()["outcome"], "reconciled")
        data = run.store.load(run.run_id)
        self.assertEqual(data["config"], original_config)
        self.assertNotIn("completion", data["operations"][-1])
        self.assertEqual(data["recoveries"]["current_context"]["current"]["package_origins"]["molecule"], str(self.site))


if __name__ == "__main__":
    unittest.main()
