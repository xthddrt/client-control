"""Solve for previously unseen RNG state triples that produce a chosen next roll."""

import functools
import importlib.util
from pathlib import Path
import struct
import sys


DIRECTORY = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("attack_rng", DIRECTORY / "attack-rng-observe.py")
model = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(model)


@functools.lru_cache(maxsize=11)
def roll_basis(roll_index=0):
    if not 0 <= roll_index <= 10:
        raise ValueError("Roll index must be from 0 to 10.")
    basis = []
    for input_bit in range(96):
        state = bytearray(0x2C)
        offset, bit = (0, 8, 0x24)[input_bit // 32], input_bit % 32
        struct.pack_into("<I", state, offset, 1 << bit)
        basis.append(model.rng_rolls(state, roll_index + 1)[0][-1])
    return basis


def state_for_rolls(targets, salt=0):
    if not targets or any(index not in range(11) or not 0 <= target <= 0xFFFFFFFF for index, target in targets.items()):
        raise ValueError("Targets must map roll indices 0..10 to 32-bit values.")
    if not 0 <= salt < 2**96:
        raise ValueError("Salt must fit in 96 bits.")
    rows = []
    for roll_index, target in sorted(targets.items()):
        basis = roll_basis(roll_index)
        for output_bit in range(32):
            coefficients = sum(((basis[input_bit] >> output_bit) & 1) << input_bit for input_bit in range(96))
            rows.append(coefficients | (((target >> output_bit) & 1) << 96))

    pivot_columns = []
    pivot_row = 0
    for column in range(96):
        pivot = next((row for row in range(pivot_row, len(rows)) if rows[row] & (1 << column)), None)
        if pivot is None:
            continue
        rows[pivot_row], rows[pivot] = rows[pivot], rows[pivot_row]
        for row in range(len(rows)):
            if row != pivot_row and rows[row] & (1 << column):
                rows[row] ^= rows[pivot_row]
        pivot_columns.append(column)
        pivot_row += 1

    for row in rows[pivot_row:]:
        if (row & ((1 << 96) - 1)) == 0 and (row >> 96) & 1:
            raise ValueError("No state satisfies all target rolls.")

    solution = salt
    for index, column in enumerate(pivot_columns):
        coefficients = rows[index] & ((1 << 96) - 1)
        parity = (coefficients & solution).bit_count() & 1
        if parity != (rows[index] >> 96) & 1:
            solution ^= 1 << column
    words = (
        solution & 0xFFFFFFFF,
        (solution >> 32) & 0xFFFFFFFF,
        (solution >> 64) & 0xFFFFFFFF,
    )
    state = bytearray(0x2C)
    for offset, word in zip((0, 8, 0x24), words):
        struct.pack_into("<I", state, offset, word)
    rolls, _ = model.rng_rolls(state)
    if any(rolls[index] != target for index, target in targets.items()):
        raise RuntimeError("Solver state did not satisfy every target roll.")
    return words


def state_for_roll(target, salt=0, roll_index=0):
    return state_for_rolls({roll_index: target}, salt)


def main():
    if len(sys.argv) not in (2, 3, 4):
        raise SystemExit("Usage: rng-state-solver.py ROLL [SALT [ROLL_INDEX]]")
    target = int(sys.argv[1], 0)
    salt = int(sys.argv[2], 0) if len(sys.argv) >= 3 else 0
    roll_index = int(sys.argv[3], 0) if len(sys.argv) == 4 else 0
    words = state_for_roll(target, salt, roll_index)
    print(" ".join(f"{word:#010x}" for word in words))


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, ValueError) as error:
        print(f"RNG state solve failed: {error}", file=sys.stderr)
        sys.exit(1)
