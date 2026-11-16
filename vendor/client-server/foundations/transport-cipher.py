"""MapleStory transport IV rolling for the fingerprinted MSCW build."""

from pathlib import Path


DEFAULT_SHUFFLE_TABLE = Path(__file__).with_name("transport-shuffle-table.bin")


def _validate_shuffle_table(table):
    table = bytes(table)
    if len(table) != 256:
        raise ValueError(f"Transport shuffle table must contain 256 bytes, got {len(table)}.")
    if sorted(table) != list(range(256)):
        raise ValueError("Transport shuffle table must be a permutation of bytes 0..255.")
    return table


def _load_shuffle_table(path):
    return _validate_shuffle_table(Path(path).read_bytes())


def getNewIv(iv, table=None):
    """Return the next four-byte IV using the saved four-round transform."""
    if not isinstance(iv, (bytes, bytearray, memoryview)):
        raise TypeError("Transport IV must be a bytes-like four-byte value.")
    iv = bytes(iv)
    if len(iv) != 4:
        raise ValueError(f"Transport IV must contain four bytes, got {len(iv)}.")
    if table is None:
        table = _load_shuffle_table(DEFAULT_SHUFFLE_TABLE)
    else:
        table = _validate_shuffle_table(table)

    new = bytearray((0xF2, 0x53, 0x50, 0xC6))
    for input_byte in iv:
        new[0] = (new[0] + table[new[1]] - input_byte) & 0xFF
        new[1] = (new[1] - (new[2] ^ table[input_byte])) & 0xFF
        new[2] = (new[2] ^ ((table[new[3]] + input_byte) & 0xFF)) & 0xFF
        new[3] = (new[3] - new[0] + table[input_byte]) & 0xFF
        value = int.from_bytes(new, "little")
        value = ((value << 3) | (value >> 29)) & 0xFFFFFFFF
        new[:] = value.to_bytes(4, "little")
    return bytes(new)
