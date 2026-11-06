# Damage RNG research toolkit

`tools-QUARANTINE/damage-rng.py` is the supported entrypoint for the damage-RNG work. It can solve for state words, replay states with exact restoration, capture attack datasets, run the 100-state maximum-damage search, and analyze results.

## What is proven

- The client RNG object is at `context+0x2998`; its generator is `0x7ac850`.
- Three 32-bit state words at object offsets `0x00`, `0x08`, and `0x24` deterministically generate an 11-roll sequence per melee attack.
- The model reproduced all 97 successful state-producing attacks in the 100-attack dataset.
- Roll index 4 is the 5% critical check: `predicted_rolls[4] / 2^32 < 0.05`. Packet byte `0x87` is the corresponding critical flag in tested packets.
- Whole-state replay changes the outgoing/displayed damage deterministically. One replayed triple produced `22` four times, and four other unique triples each produced `30`.
- The 100-state maximum-damage search produced `34` nineteen times and did not produce `35`.
- Roll 2 controls the main base-damage input. Roll 3 sets a useful damage ceiling: `30 + ceil(4 * roll3 / 2^32)`. That formula matched 70 of 96 usable search attacks exactly; all remaining results were lower.
- High roll 5 and low roll 9 values are reduction candidates, not yet independently proven modifiers.

The three state words matter through the rolls they generate, not through independent damage meanings. Final damage also depends on equipment, action, target stats, and other modifiers. Outgoing/displayed damage is proven; authoritative server HP loss has not been decoded.

## Setup

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python tools-QUARANTINE/damage-rng.py self-test
```

Live commands auto-detect the single running `MapleStory.exe` process. They need sudo for `/proc/PID/mem` and ptrace on hosts with `ptrace_scope=1`. No NGS HTTP proxy is used for these experiments.

## Solve state words for target rolls

One target:

```bash
.venv/bin/python tools-QUARANTINE/damage-rng.py solve --roll 4=0
```

Maximum base-damage roll plus a critical:

```bash
.venv/bin/python tools-QUARANTINE/damage-rng.py solve --roll 2=0xffffffff --roll 4=0
# b95365e0 e2793d38 000000d0
```

Roll indices are `0..10`, and values are 32-bit integers. `--salt N` varies free state bits when alternatives exist. Simultaneous targets can be inconsistent; the solver reports that rather than inventing a state.

## Replay a state

```bash
sudo .venv/bin/python tools-QUARANTINE/damage-rng.py replay \
  --words 0x178e8921 0xa8fc3ce8 0x000000e4 \
  --replays 1 --seconds 60 --output captures/rng-34-replay.json
```

Or replay a solver-selected state:

```bash
sudo .venv/bin/python tools-QUARANTINE/damage-rng.py replay \
  --roll 2=0xffffffff --roll 4=0 \
  --replays 1 --output captures/rng-max-replay.json
```

The experiment performs native, unchanged-write, and replayed-state attacks. It verifies each write and restores the complete original 44-byte RNG object before detaching.

## Capture an attack dataset

```bash
sudo .venv/bin/python tools-QUARANTINE/damage-rng.py capture \
  --count 100 --seconds 1800 --output captures/rng-100.jsonl
```

JSONL records are flushed after every attack. They include pre/post state words, all 11 predicted rolls, damage, full melee body, and transition validation. Existing files resume at the next attack index.

## Run and analyze the maximum-damage search

```bash
sudo .venv/bin/python tools-QUARANTINE/damage-rng.py search
.venv/bin/python tools-QUARANTINE/damage-rng.py analyze captures/rng-max-100-results.jsonl
```

The search uses roll 2 `0xffffffff` or `0xfffffffe` and a critical roll 4, with 100 distinct 11-roll sequences. Every candidate restores the original state. Rerunning resumes from the first untested candidate.

A reproducible `34` state from the search is:

```text
178e8921 a8fc3ce8 000000e4
```

Its roll 2 is `0xfffffffe`, and its roll 4 is `0x00100000`, which is critical.

## Supporting modules

- `rng-state-solver.py`: GF(2) solver for single or simultaneous roll targets.
- `rng-state-override.py`: exact state writes/readbacks, repeated replay, and restoration.
- `rng-roll-override.py`: replay a solver-generated state for a chosen roll/index.
- `rng-dataset.py`: streaming attack-dataset recorder.
- `rng-max-search.py`: candidate generation and resumable maximum-damage search.
- `rng-damage-override.py`: narrower negative experiment replacing one damage-roll register.
- `rng-write-watch.py`: identifies actual RNG state writers through hardware watchpoints.

Use `HANDOFF.md` for the chronological research evidence and remaining unknowns. Run only one ptrace observer at a time, stop with SIGINT when necessary, and verify `TracerPid=0` afterward. Live modification and repeated maximum-damage attacks can trigger server-side plausibility enforcement or account penalties.
