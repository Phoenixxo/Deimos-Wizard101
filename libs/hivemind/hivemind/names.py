"""Compact wizard-name codec for the NAME protocol message.

The chat receive hook only exposes a sender's GID, never their name, so peers
exchange their own ``client.wizard_name`` over the protocol. Names don't fit a
single 79-char steg whisper as raw text, so we pack them into a small integer
using a fixed alphabet (space + a-z + A-Z + apostrophe, ~6 bits/char, so inner
caps like "StormStalker" survive) and split them into chunks that each fit one
message; the receiver reassembles them.
"""

from typing import List

_ALPHABET = " abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'"
_BASE = len(_ALPHABET)  # 54
_INDEX = {c: i for i, c in enumerate(_ALPHABET)}

# Chars per NAME chunk. Kept small so the encoded steg sentence stays under the
# 79-char whisper cap even with the protocol's fixed framing/checksum overhead.
CHUNK_SIZE = 8
_MAX_NAME = CHUNK_SIZE * 8  # sanity cap on absurd names


def normalize_name(name: str) -> str:
    """Keep only alphabet chars (others -> space), trimmed."""
    out = [(ch if ch in _INDEX else " ") for ch in (name or "")]
    return "".join(out).strip()[:_MAX_NAME]


def pack_chunk(chars: str) -> int:
    """Pack chars into an int. A leading-1 sentinel preserves leading spaces
    and the exact length."""
    value = 1
    for ch in chars:
        value = value * _BASE + _INDEX.get(ch, 0)
    return value


def unpack_chunk(value: int) -> str:
    """Inverse of ``pack_chunk``."""
    out = []
    while value > 1:
        value, rem = divmod(value, _BASE)
        out.append(_ALPHABET[rem])
    return "".join(reversed(out))


def chunk_name(name: str) -> List[str]:
    """Split a (normalized) name into CHUNK_SIZE-char pieces."""
    norm = normalize_name(name)
    return [norm[i:i + CHUNK_SIZE] for i in range(0, len(norm), CHUNK_SIZE)] or [""]
