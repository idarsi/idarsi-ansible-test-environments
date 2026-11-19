"""Read-only bridge to the active environment's actual Molecule config API.

Executed separately so importing the supervisor remains stdlib-only. No
dependency installation or Molecule lifecycle command is performed.
"""

import json
import os
import sys

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
    config = ManagedConfig(
        sys.argv[1],
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
    data["_idarsi_effective_env"] = config.env
    # Molecule may replace console streams during configuration. Keep the
    # machine response on the original stream and flush before interpreter exit.
    sys.__stdout__.write(json.dumps(data) + "\n")
    sys.__stdout__.flush()


if __name__ == "__main__":
    main()
