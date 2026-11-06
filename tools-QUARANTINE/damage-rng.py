"""Damage RNG research toolkit: solve, replay, capture, search, and analyze."""

import argparse
import collections
import importlib.util
import json
import os
from pathlib import Path
import struct
import sys


DIRECTORY = Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


solver = load("rng_state_solver", DIRECTORY / "rng-state-solver.py")
experiment = load("rng_state_override", DIRECTORY / "rng-state-override.py")
dataset = load("rng_dataset", DIRECTORY / "rng-dataset.py")
search = load("rng_max_search", DIRECTORY / "rng-max-search.py")
character = experiment.character
PROFILE = experiment.PROFILE


def auto_pid():
    return character.find_pid(PROFILE["process_name"])


def chown_output(path):
    if Path(path).exists() and "SUDO_UID" in os.environ and "SUDO_GID" in os.environ:
        os.chown(path, int(os.environ["SUDO_UID"]), int(os.environ["SUDO_GID"]))


def roll_targets(values):
    targets = {}
    for value in values:
        index, target = value.split("=", 1)
        targets[int(index, 0)] = int(target, 0)
    return targets


def solve(args):
    words = solver.state_for_rolls(roll_targets(args.roll), args.salt)
    print(" ".join(f"{word:#010x}" for word in words))


def replay(args):
    targets = roll_targets(args.roll)
    words = solver.state_for_rolls(targets, args.salt) if targets else tuple(int(value, 0) for value in args.words)
    if len(words) != 3:
        raise ValueError("Replay requires exactly three state words.")
    print(f"REPLAY state={' '.join(f'{word:#010x}' for word in words)}", flush=True)
    try:
        experiment.run(auto_pid(), args.seconds, args.output, args.replays, words)
    finally:
        chown_output(args.output)


def capture(args):
    try:
        dataset.run(auto_pid(), args.seconds, args.output, args.count)
    finally:
        chown_output(args.output)


def maximum_search(args):
    candidate_path = Path(args.candidates)
    if not candidate_path.exists():
        candidates = search.make_candidates()
        descriptor = os.open(candidate_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(candidates, stream, indent=1)
        chown_output(candidate_path)
        print(f"WROTE {candidate_path}: 100 unique states and roll sequences.")
    try:
        search.run(auto_pid(), args.seconds, candidate_path, args.output)
    finally:
        chown_output(args.output)


def analyze(args):
    records = [
        json.loads(line) for line in Path(args.results).read_text().splitlines()
        if line.strip() and "index" in line
    ]
    if not records:
        raise ValueError("No attack records found.")
    counts = collections.Counter(record.get("damage") for record in records)
    maximum = max(damage for damage in counts if damage is not None)
    print(f"attacks={len(records)} restored={sum(record.get('state_restored', False) for record in records)}")
    print(f"maximum_damage={maximum}")
    for damage, count in sorted(counts.items(), key=lambda item: (item[0] is not None, item[0]), reverse=True):
        print(f"damage={damage} count={count}")
    print("top_states:")
    for record in sorted(records, key=lambda record: record.get("damage") or -1, reverse=True)[:10]:
        words = " ".join(f"{word:#010x}" for word in record["words"])
        print(f"  index={record['index']} damage={record.get('damage')} state={words}")


def self_test():
    words = solver.state_for_roll(1, 0, 4)
    state = bytearray(0x2C)
    for offset, word in zip((0, 8, 0x24), words):
        struct.pack_into("<I", state, offset, word)
    rolls, _ = experiment.model.rng_rolls(state)
    assert rolls[4] == 1 and rolls[4] / 2**32 < 0.05
    candidates = search.make_candidates()
    assert len(candidates) == 100
    assert len({tuple(candidate["words"]) for candidate in candidates}) == 100
    assert len({tuple(candidate["expected_rolls"]) for candidate in candidates}) == 100
    assert all(candidate["roll2"] in (0xFFFFFFFF, 0xFFFFFFFE) for candidate in candidates)
    assert all(candidate["roll4"] / 2**32 < 0.05 for candidate in candidates)
    assert solver.state_for_roll(0x12345678) == solver.state_for_roll(0x12345678)
    print("PASS: solver, critical threshold, and 100 unique maximum-damage candidates.")


def parser():
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)

    def rolls(subparser):
        subparser.add_argument("--roll", action="append", default=[], metavar="INDEX=VALUE", help="Target roll; repeat for multiple indices.")
        subparser.add_argument("--salt", type=lambda value: int(value, 0), default=0)

    solve_parser = commands.add_parser("solve", help="Solve state words for one or more target rolls.")
    rolls(solve_parser)
    solve_parser.set_defaults(function=solve)

    replay_parser = commands.add_parser("replay", help="Replay a state with restoration after each attack.")
    rolls(replay_parser)
    replay_parser.add_argument("--words", nargs=3, default=["0x0c2418d6", "0xcdf84fe7", "0x5e613e0a"])
    replay_parser.add_argument("--replays", type=int, default=1)
    replay_parser.add_argument("--seconds", type=float, default=60)
    replay_parser.add_argument("--output", default="captures/rng-replay.json")
    replay_parser.set_defaults(function=replay)

    capture_parser = commands.add_parser("capture", help="Capture attack states, rolls, and damage as JSONL.")
    capture_parser.add_argument("--count", type=int, default=100)
    capture_parser.add_argument("--seconds", type=float, default=1800)
    capture_parser.add_argument("--output", default="captures/rng-100.jsonl")
    capture_parser.set_defaults(function=capture)

    search_parser = commands.add_parser("search", help="Test 100 near-maximum damage states with resume support.")
    search_parser.add_argument("--candidates", default="captures/rng-max-100-candidates.json")
    search_parser.add_argument("--output", default="captures/rng-max-100-results.jsonl")
    search_parser.add_argument("--seconds", type=float, default=1800)
    search_parser.set_defaults(function=maximum_search)

    analyze_parser = commands.add_parser("analyze", help="Summarize a maximum-search JSONL result file.")
    analyze_parser.add_argument("results")
    analyze_parser.set_defaults(function=analyze)

    test_parser = commands.add_parser("self-test", help="Run offline solver and candidate checks.")
    test_parser.set_defaults(function=lambda args: self_test())
    return root


def main():
    args = parser().parse_args()
    args.function(args)


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, ValueError, struct.error) as error:
        print(f"Damage RNG command failed: {error}", file=sys.stderr)
        sys.exit(1)
