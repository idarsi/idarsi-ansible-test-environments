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

_diagnostics = None


def reject(message):
    diagnostic(message)
    raise SystemExit(1)


def diagnostic(message):
    """Emit only caller-owned finite reasons, never dependency exception text."""
    try:
        print(message, file=_diagnostics or sys.__stderr__, flush=True)
    except (OSError, ValueError):
        pass


def load_config(source):
    """Import Molecule only inside the already isolated child."""
    from molecule.config import Config
    from molecule.shell import LOCAL_CONFIG

    class ManagedConfig(Config):
        """Reject shared-state dispatch before default-scenario resolution."""

        def _get_config(self):
            data = super()._get_config()
            if data.get("shared_state") or data.get("scenario", {}).get("shared_state"):
                reject("Managed runs reject shared_state configuration")
            return data

    return ManagedConfig(
        source,
        args={
            "base_config": [LOCAL_CONFIG] if LOCAL_CONFIG else [],
            "env_file": os.environ.get("MOLECULE_ENV_FILE", ".env.yml"),
        },
        command_args={"parallel": False},
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("source")
    parser.add_argument("--supervised", action="store_true")
    args = parser.parse_args()
    if args.supervised:
        validate_controller()
    config = load_config(args.source)
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
    return data


def child_main():
    """Own private protocol descriptors; discard all ordinary dependency output."""
    global _diagnostics
    try:
        with os.fdopen(os.dup(2), "w") as errors:
            # os.dup returns non-inheritable descriptors. Only these wrappers own
            # the duplicates; trusted exec children receive neither protocol FD.
            _diagnostics = errors
            try:
                with os.fdopen(os.dup(1), "wb") as response:
                    sink = os.open(os.devnull, os.O_WRONLY)
                    try:
                        os.dup2(sink, 1)
                        os.dup2(sink, 2)
                    finally:
                        os.close(sink)
                    # Never restore FD 1/2: buffered streams, atexit handlers and
                    # exec children stay on the sink during interpreter shutdown.
                    payload = (json.dumps(main()) + "\n").encode("utf-8")
                    response.write(payload)
                    response.flush()
            except Exception:
                diagnostic("config_bridge_failed")
                return 1
        return 0
    except Exception:
        diagnostic("config_bridge_failed")
        return 1


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
    raise SystemExit(child_main())
