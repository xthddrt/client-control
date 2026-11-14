"""Safe extraction of a zipped session bundle (no external tool needed)."""

from __future__ import annotations

import re
import shutil
import tempfile
import zipfile
from pathlib import Path

ALLOWED = re.compile(
    r"^(events\.jsonl(\.\d+)?|events\.pcapng(\.\d+)?|"
    r"capture\.pcap|attribution\.jsonl|capture\.json|"
    r"manifest\.json|session_meta\.json|checksums\.json)$"
)


def extract_bundle(path):
    """Extract only known session files to a new temporary directory.

    Returns (directory, extracted_paths). The caller owns and must remove the
    directory.
    """
    path = Path(path)
    directory = Path(tempfile.mkdtemp(prefix="client-control-session-"))
    extracted = []
    try:
        with zipfile.ZipFile(path) as archive:
            for member in archive.infolist():
                if member.is_dir():
                    continue
                name = Path(member.filename).name
                if not ALLOWED.match(name):
                    continue
                target = directory / name
                with archive.open(member) as source, open(target, "wb") as output:
                    shutil.copyfileobj(source, output)
                extracted.append(target)
    except Exception:
        shutil.rmtree(directory, ignore_errors=True)
        raise
    return directory, extracted
