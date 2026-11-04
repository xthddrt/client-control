"""Validation for build-specific CMob and movement-controller offsets."""


MOB_OFFSET_NAMES = frozenset({
    "cmob_vtable_rva", "cvecctrl_vtable_rva", "ctrl_a", "ctrl_b",
    "x", "y", "y2", "x_post", "vx", "vy", "b_rel", "b_rel2",
    "b_vrel", "b_vrel2", "fh_enc", "fh_plain", "mob_id", "hp", "controlled",
})


def _offset(name, value):
    if isinstance(value, bool):
        raise ValueError(f"Mob offset {name} must be an integer, not a boolean.")
    try:
        if isinstance(value, str):
            converted = int(value, 0)
        elif isinstance(value, int):
            converted = value
        elif isinstance(value, float) and value.is_integer():
            converted = int(value)
        else:
            raise ValueError
    except (TypeError, ValueError) as error:
        raise ValueError(f"Mob offset {name} is not an exact integer: {value!r}.") from error
    if not 0 <= converted <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError(f"Mob offset {name} is outside the unsigned 64-bit range.")
    return converted


def load_mob_offsets(profile):
    try:
        values = profile["mob_offsets"]
    except (KeyError, TypeError) as error:
        raise ValueError("Profile has no mob_offsets mapping.") from error
    if not isinstance(values, dict):
        raise ValueError("Profile mob_offsets must be a mapping.")
    names = set(values)
    if names != MOB_OFFSET_NAMES:
        missing = sorted(MOB_OFFSET_NAMES - names)
        unknown = sorted(names - MOB_OFFSET_NAMES)
        raise ValueError(f"Mob offset schema mismatch; missing={missing}, unknown={unknown}.")
    return {name: _offset(name, values[name]) for name in MOB_OFFSET_NAMES}
