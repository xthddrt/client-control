"""Replay a solver-generated state triple for a chosen next RNG roll."""

import importlib.util
from pathlib import Path
import sys


DIRECTORY = Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


solver = load("rng_state_solver", DIRECTORY / "rng-state-solver.py")
experiment = load("rng_state_override", DIRECTORY / "rng-state-override.py")


def main():
    if len(sys.argv) not in (5, 6, 7, 8):
        raise SystemExit("Usage: rng-roll-override.py PID|auto SECONDS OUT.json ROLL [REPLAYS [SALT [ROLL_INDEX]]]")
    duration = float(sys.argv[2])
    if not 1 <= duration <= 600:
        raise SystemExit("Use a capture duration from 1 to 600 seconds.")
    target = int(sys.argv[4], 0)
    replays = int(sys.argv[5]) if len(sys.argv) >= 6 else 1
    salt = int(sys.argv[6], 0) if len(sys.argv) >= 7 else 0
    roll_index = int(sys.argv[7], 0) if len(sys.argv) == 8 else 0
    if not 1 <= replays <= 10:
        raise SystemExit("Use 1 to 10 replay attacks.")
    words = solver.state_for_roll(target, salt, roll_index)
    pid = experiment.character.find_pid(experiment.PROFILE["process_name"]) if sys.argv[1] == "auto" else int(sys.argv[1])
    print(f"TARGET roll={target:#010x} index={roll_index} state={' '.join(f'{word:#010x}' for word in words)}", flush=True)
    experiment.run(pid, duration, sys.argv[3], replays, words)


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, ValueError) as error:
        print(f"Chosen-roll experiment failed: {error}", file=sys.stderr)
        sys.exit(1)
