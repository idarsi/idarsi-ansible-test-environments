"""Test-only policy seam for genuine Molecule parser regression fixtures.

Portable CI installs Molecule, not an approved Idarsi controller. These tests
exercise actual parsing, relocation and shared-state guards, independently of
controller admission. Replace only that pure policy function in the child;
never manufacture VIRTUAL_ENV, sys.prefix, a controller tree or a production
override. Explicit installed-lane tests exercise the unmodified policy.
"""

import contextlib
import importlib.util
from pathlib import Path
import sys
from unittest.mock import patch


@contextlib.contextmanager
def portable_controller_policy():
    from isolated_runs import cli

    original = cli.command

    def command(argv, **kwargs):
        if len(argv) < 3 or Path(argv[1]) != cli.REPO / "scripts/isolated_runs/molecule_config.py":
            raise AssertionError("Portable parser fixture received a non-bridge command")
        return original([sys.executable, "-B", __file__, *argv[1:]], **kwargs)

    with patch.object(cli, "command", side_effect=command):
        yield


def main():
    source = Path(sys.argv[1])
    spec = importlib.util.spec_from_file_location("portable_molecule_bridge", source)
    bridge = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bridge)
    sys.argv = [str(source), *sys.argv[2:]]
    with patch.object(bridge, "validate_controller", autospec=True) as policy:
        result = bridge.child_main()
        if "--supervised" in sys.argv:
            policy.assert_called_once_with()
        else:
            policy.assert_not_called()
        raise SystemExit(result)


if __name__ == "__main__":
    main()
