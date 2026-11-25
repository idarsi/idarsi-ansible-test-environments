"""Read-only bridge to the active environment's actual Molecule config API.

Executed separately so importing the supervisor remains stdlib-only. No
dependency installation or Molecule lifecycle command is performed.
"""

import argparse
import json
import os
from pathlib import Path
import sys

if __name__ == "__main__" and "--existing-only" in sys.argv:
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    try:
        from isolated_runs.existing_config import bridge_main
        from isolated_runs.guest_refusal import GuestRefusal

        if len(sys.argv) != 4 or sys.argv[2] != "--existing-only":
            raise GuestRefusal("AUTHORITY_PARSE")
        bridge_main(sys.argv[1], sys.argv[3])
    except Exception as error:
        from isolated_runs.guest_refusal import emit

        emit(error, stream=sys.__stderr__)
        raise SystemExit(1) from None
    raise SystemExit(0)

from molecule.config import Config
from molecule.shell import LOCAL_CONFIG


def reject(message):
    # Molecule configures console streams on import. Keep guard diagnostics on
    # the original error stream, without dumping the potentially secret config.
    print(message, file=sys.__stderr__)
    raise SystemExit(1)


class ManagedConfig(Config):
    """Reject shared-state dispatch before Molecule resolves the default scenario."""

    def _get_config(self):
        data = super()._get_config()
        if data.get("shared_state") or data.get("scenario", {}).get("shared_state"):
            reject("Managed runs reject shared_state configuration")
        return data


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("source")
    parser.add_argument("--supervised", action="store_true")
    args = parser.parse_args()
    if args.supervised:
        validate_controller()
    config = ManagedConfig(
        args.source,
        args={
            "base_config": [LOCAL_CONFIG] if LOCAL_CONFIG else [],
            "env_file": os.environ.get("MOLECULE_ENV_FILE", ".env.yml"),
        },
        command_args={"parallel": False},
    )
    if not hasattr(config, "config_data"):
        config.after_init()
        data = config.config
    else:
        data = config.config_data
    if config.is_parallel or data.get("shared_state") or data.get("scenario", {}).get("shared_state"):
        reject("Managed runs reject parallel/shared_state configuration")
    if data["scenario"]["test_sequence"] != config._get_defaults()["scenario"]["test_sequence"]:
        reject("Managed runs require the default full test sequence")
    data["_idarsi_effective_ephemeral"] = str(config.scenario.ephemeral_directory)
    data["_idarsi_effective_scenario"] = config.scenario.name
    data["_idarsi_effective_role"] = str(config.project_directory)
    environment = dict(config.env)
    for key in ("VIRTUAL_ENV", "IDARSI_TEST_ENVIRONMENT"):
        if key in os.environ:
            environment[key] = os.environ[key]
    data["_idarsi_effective_env"] = environment
    # Molecule may replace console streams during configuration. Keep the
    # machine response on the original stream and flush before interpreter exit.
    sys.__stdout__.write(json.dumps(data) + "\n")
    sys.__stdout__.flush()


def validate_controller():
    """Require observed activation to bind this bridge to its approved controller."""
    root = Path(__file__).resolve().parents[2]
    helper = os.environ.get("IDARSI_TEST_ENVIRONMENT", "")
    activation = os.environ.get("VIRTUAL_ENV", "")
    if not helper or not activation:
        reject("controller_binding_missing")
    try:
        helper_path, prefix = Path(helper), Path(activation)
        approved_prefixes = set()
        for lane in ("ansible-min", "ansible-current", "ansible-next"):
            try:
                approved_prefixes.add((root / ".venv" / lane).resolve(strict=True))
            except FileNotFoundError:
                continue
        valid = (
            helper_path.is_absolute() and helper_path.resolve(strict=True) == root
            and helper_path.is_dir() and prefix.is_dir() and prefix.is_absolute()
            and prefix.resolve(strict=True) in approved_prefixes
            and Path(sys.prefix).resolve(strict=True) == prefix.resolve(strict=True)
            and Path(sys.prefix).resolve() != Path(sys.base_prefix).resolve()
            and Path(sys.executable).absolute().parent.resolve() == prefix.resolve() / "bin"
            and Path(sys.executable).is_file() and (prefix / "bin/python3").is_file()
        )
    except (OSError, RuntimeError, ValueError):
        valid = False
    if not valid:
        reject("controller_binding_conflict")


if __name__ == "__main__":
    main()
