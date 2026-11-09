# Applicable tools

User-facing capabilities built from `foundations/` and `analysis/`. Run commands from the repository root.

## Main entrypoints

```bash
.venv/bin/python tools/position-gui.py
.venv/bin/python tools/damage-rng.py self-test
```

- `position-gui.py`: GUI orchestration for VAC/park, combat modifiers, portals, launch controls, and hotkeys.
- `vac-sprites.py`: mob VAC and park engine.
- `damage-rng.py`: supported solve, replay, capture, search, and analysis interface; its solver/replay helpers remain here, while observation and experiments live in `analysis/`.
- `atkspeed.py` and `atkspeed-frames.py`: attack-rate experiments.
- `overhead-attacks.py` and `try-collision-miss.py`: overhead-hitbox and collision-MISS capabilities.
- `m2-detour.py`, `sendpacket-drop.py`, and the telemetry-shield scripts: anti-disconnect and telemetry controls with their original limits.

Read the [arsenal](../docs/research/01-THE-ARSENAL.md), [RNG guide](../docs/guides/DAMAGE-RNG.md), and [live-validation record](../docs/research/LIVE-VALIDATION.md) before running anything. The directory name no longer says quarantine, but the safety and authorization requirements are unchanged.
