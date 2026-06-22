"""ChatStegCipher: encode protocol messages as natural-looking chat.

The wire format ``HM P0`` / ``HM H0 0 2 0`` is trivially fingerprintable. This
layer instead renders each message as a short sentence built **only** from
words observed in a reference corpus (``data/chatlog_p1.txt``), drawn to match
that corpus's statistical distribution -- so the output is, by construction, a
sample of the same bigram model real player chat follows.

How it stays reversible AND distribution-matching:

  * A **bigram model** over the corpus vocabulary (+ an end-of-sentence symbol)
    is built deterministically with integer-only arithmetic, so both clients
    derive byte-identical frequency tables.
  * The structured message (type + args) is serialized to a few bytes and
    **whitened** with a shared-key keystream so its bits look uniform. (rANS
    only reproduces the model's distribution when fed uniform bits; whitening
    is also the "cipher" / confidentiality layer.)
  * A **range coder (rANS)** turns the whitened bits into words by *decoding*
    them through the model, and recovers them by *encoding* the words back.
    Exact integer math (Python big-ints + byte renormalization) makes the
    round-trip bit-exact.

This module is self-contained (stdlib only) so it travels with the subtree.
"""

import hashlib
import os
import re
from functools import lru_cache
from importlib import resources
from typing import Dict, List, Optional, Tuple

from .message_type import MessageType


# ----- model parameters -----

# Per-context total frequency (must divide RANS_L). Larger = finer probability
# resolution = closer distribution match, at a little more state width.
TOTAL = 1 << 14                 # 16384
# rANS normalization window. State is kept in [RANS_L, RANS_L * 256).
RANS_L = 1 << 24               # multiple of TOTAL (1<<24 / 1<<14 = 1<<10)
RANS_BYTE = 1 << 8

# Smoothing weights (integer). A candidate word's weight in a context is
#   bigram_count * BIGRAM_W + unigram_count * UNIGRAM_W + 1
# The +1 floor gives every vocab word non-zero probability in every context
# (full support), which the coder requires.
BIGRAM_W = 64
UNIGRAM_W = 4

# End-of-sentence symbol weight. Tuned so mean sentence length tracks the
# corpus (~4.6 words/line): a per-context EOS weight derived from how often a
# context actually ended a line, plus a small floor.
EOS_CONTEXT_W = 48
EOS_FLOOR = 8

_WORD_RE = re.compile(r"[a-z0-9]+")


def _corpus_lines() -> List[str]:
    text = resources.files(__package__).joinpath("data/chatlog_p1.txt").read_text(encoding="utf-8")
    return [ln.strip() for ln in text.splitlines() if ln.strip()]


def _tokenize(line: str) -> List[str]:
    # Lowercase, keep only transport-safe [a-z0-9] tokens (matches the 96.5%
    # of corpus tokens that survive the chat filter without emoji).
    return _WORD_RE.findall(line.lower())


class _Model:
    """Deterministic bigram model over the corpus vocabulary + EOS.

    Symbols: word ids 0..V-1, and EOS = V.
    Contexts: previous word id 0..V-1, and BOS = V (sentence start).
    """

    def __init__(self):
        lines = _corpus_lines()

        vocab = set()
        for ln in lines:
            vocab.update(_tokenize(ln))
        self.words: List[str] = sorted(vocab)              # deterministic order
        self.word_id: Dict[str, int] = {w: i for i, w in enumerate(self.words)}
        self.V = len(self.words)
        self.EOS = self.V
        self.BOS = self.V
        self.n_symbols = self.V + 1

        # Counts.
        self.unigram = [0] * self.V
        # bigram[ctx] = {sym: count}; ctx in 0..V (BOS=V), sym in 0..V (EOS=V)
        self.bigram: List[Dict[int, int]] = [dict() for _ in range(self.V + 1)]

        for ln in lines:
            toks = [self.word_id[w] for w in _tokenize(ln) if w in self.word_id]
            if not toks:
                continue
            prev = self.BOS
            for wid in toks:
                self.unigram[wid] += 1
                self.bigram[prev][wid] = self.bigram[prev].get(wid, 0) + 1
                prev = wid
            # sentence ends: prev -> EOS
            self.bigram[prev][self.EOS] = self.bigram[prev].get(self.EOS, 0) + 1

        self._total_unigram = sum(self.unigram)

    # ---- per-context frequency table (integer, sums to TOTAL) ----

    @lru_cache(maxsize=8192)
    def freqs(self, ctx: int, allow_eos: bool = True) -> Tuple[Tuple[int, ...], Tuple[int, ...]]:
        """Return (freq, cum) for a context: integer frequencies over all
        n_symbols that sum to exactly TOTAL, plus the exclusive cumulative
        table. Pure-integer + deterministic.

        Symbol order is **EOS first** (index 0), then word ids 0..V-1 at
        indices 1..V. When ``allow_eos`` is False, EOS gets frequency 0 (the
        words alone sum to TOTAL); the coder suppresses EOS while the state is
        large so the message is fully consumed and termination only happens at
        the bottom of the range (with a small, trial-able residue).
        """
        ctx_bigram = self.bigram[ctx]

        weights = [0] * self.n_symbols
        if allow_eos:
            weights[0] = ctx_bigram.get(self.EOS, 0) * EOS_CONTEXT_W + EOS_FLOOR
        for wid in range(self.V):
            w = ctx_bigram.get(wid, 0) * BIGRAM_W + self.unigram[wid] * UNIGRAM_W + 1
            weights[wid + 1] = w

        total_w = sum(weights)

        # Floor: every symbol that may appear gets >= 1 (EOS gets 0 when
        # suppressed). Distribute the remaining units by weight.
        floors = [0 if (s == 0 and not allow_eos) else 1 for s in range(self.n_symbols)]
        spare = TOTAL - sum(floors)
        freq = list(floors)
        for sym in range(self.n_symbols):
            if floors[sym]:
                freq[sym] += (weights[sym] * spare) // total_w

        # Fix the rounding deficit deterministically (heaviest weights first).
        deficit = TOTAL - sum(freq)
        if deficit:
            order = sorted((s for s in range(self.n_symbols) if floors[s]),
                           key=lambda s: (-weights[s], s))
            for i in range(deficit):
                freq[order[i % len(order)]] += 1

        cum = [0] * (self.n_symbols + 1)
        for s in range(self.n_symbols):
            cum[s + 1] = cum[s] + freq[s]
        return tuple(freq), tuple(cum)

    def symbol_for_slot(self, ctx: int, slot: int, allow_eos: bool = True) -> int:
        _, cum = self.freqs(ctx, allow_eos)
        # binary search: largest s with cum[s] <= slot
        lo, hi = 0, self.n_symbols
        while lo + 1 < hi:
            mid = (lo + hi) // 2
            if cum[mid] <= slot:
                lo = mid
            else:
                hi = mid
        return lo


# Lazily-built shared singleton (building scans the corpus once).
_MODEL: Optional[_Model] = None


def _model() -> _Model:
    global _MODEL
    if _MODEL is None:
        _MODEL = _Model()
    return _MODEL


# ----- no-renormalization big-integer rANS (exact bijection) -----
#
# Symbol space (freqs ordering): position 0 = EOS, position w+1 = word id w.
# decode_int(X) pops symbols (each step strictly shrinks X) until EOS, which
# sits at the bottom of every range so the walk always reaches it. It leaves a
# small residue r in [0, f_eos[last_ctx]); encode_int(words, r) is its exact
# inverse. The receiver doesn't know r, so it trials the (few) possibilities
# and keeps the one whose framed bytes pass the checksum.

_EOS_POS = 0


def _decode_int(x: int) -> Tuple[List[int], int]:
    """Pop a word-id sequence out of integer state ``x``. Returns (words, r)
    where r < f_eos[last_ctx] is the leftover residue.

    EOS is suppressed while ``x >= TOTAL`` (the high, message-carrying part)
    so the whole payload is consumed and termination only happens once the
    state has shrunk below TOTAL -- giving a small, trial-able residue."""
    m = _model()
    ctx = m.BOS
    words: List[int] = []
    while True:
        allow = x < TOTAL
        freq, cum = m.freqs(ctx, allow)
        slot = x % TOTAL
        sym = m.symbol_for_slot(ctx, slot, allow)
        x = freq[sym] * (x // TOTAL) + slot - cum[sym]
        if sym == _EOS_POS:
            return words, x
        wid = sym - 1
        words.append(wid)
        ctx = wid


def _push(x: int, ctx: int, sym: int, allow_eos: bool) -> int:
    freq, cum = _model().freqs(ctx, allow_eos)
    f, c = freq[sym], cum[sym]
    return (x // f) * TOTAL + (x % f) + c


def _encode_int(words: List[int], residue: int) -> int:
    """Exact inverse of ``_decode_int``: fold ``words`` (+ EOS) back into the
    integer state, starting from ``residue``. Each word is pushed with the same
    EOS-suppression decision the decoder will make (based on the resulting
    state's magnitude)."""
    m = _model()
    contexts = [m.BOS] + list(words)          # context of each word
    last_ctx = words[-1] if words else m.BOS
    # push EOS first (it was popped last), with EOS allowed (bottom of range)
    x = _push(residue, last_ctx, _EOS_POS, True)
    for i in range(len(words) - 1, -1, -1):
        sym = words[i] + 1
        ctx = contexts[i]
        # Decoder uses the no-EOS table iff the pre-pop state (== this post-push
        # state) is >= TOTAL. Push the suppressed way if that keeps us >= TOTAL.
        xn = _push(x, ctx, sym, False)
        x = xn if xn >= TOTAL else _push(x, ctx, sym, True)
    return x


def _max_eos_freq(last_ctx: int) -> int:
    """Upper bound (exclusive) on the residue for a given trailing context."""
    freq, _ = _model().freqs(last_ctx, True)
    return freq[_EOS_POS]


# ----- whitening (shared-key keystream over the body) -----

def _keystream(key: bytes, n: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < n:
        out += hashlib.sha256(key + counter.to_bytes(4, "big")).digest()
        counter += 1
    return bytes(out[:n])


def _whiten(data: bytes, key: bytes) -> bytes:
    ks = _keystream(key, len(data))
    return bytes(b ^ k for b, k in zip(data, ks))


# ----- message framing -----

# Number of integer args each message type carries (so the parser knows how
# many varints to read after the type byte).
_ARG_COUNT = {
    MessageType.PING: 0,
    MessageType.PONG: 0,
    MessageType.HELLO: 3,
    MessageType.HELLO_ACK: 3,
    MessageType.BOT_OFFER: 1,
    MessageType.BOT_ACCEPT: 1,
    MessageType.BOT_REJECT: 1,
    MessageType.KEEPALIVE: 1,
    MessageType.KEEPALIVE_ACK: 1,
    MessageType.SESSION_PAUSE: 0,
    MessageType.SESSION_RESUME: 0,
    MessageType.SESSION_END: 0,
    MessageType.SESSION_LEFT: 0,
    MessageType.NAME: 3,
}
_TYPE_BY_VALUE = {t.value: t for t in MessageType}


def _zigzag(n: int) -> int:
    return (2 * n) if n >= 0 else (-2 * n - 1)


def _unzigzag(u: int) -> int:
    return (u >> 1) if (u & 1) == 0 else -((u + 1) >> 1)


def _put_varint(buf: bytearray, u: int):
    while True:
        b = u & 0x7F
        u >>= 7
        if u:
            buf.append(b | 0x80)
        else:
            buf.append(b)
            return


def _get_varint(data: bytes, i: int) -> Tuple[int, int]:
    u = 0
    shift = 0
    while True:
        b = data[i]
        i += 1
        u |= (b & 0x7F) << shift
        if not (b & 0x80):
            return u, i
        shift += 7


def _serialize(msg_type: MessageType, args: List[int]) -> bytes:
    buf = bytearray([msg_type.value])
    for a in args:
        _put_varint(buf, _zigzag(a))
    return bytes(buf)


def _deserialize(body: bytes) -> Optional[Tuple[MessageType, List[int]]]:
    if not body:
        return None
    msg_type = _TYPE_BY_VALUE.get(body[0])
    if msg_type is None:
        return None
    n = _ARG_COUNT[msg_type]
    args: List[int] = []
    i = 1
    try:
        for _ in range(n):
            u, i = _get_varint(body, i)
            args.append(_unzigzag(u))
    except IndexError:
        return None
    if i != len(body):
        return None  # trailing garbage -> wrong candidate
    return msg_type, args


# 4-byte body digest. The receiver finds the right residue by trialing a few
# hundred candidates; a short checksum would collide, so use 32 bits (false
# accept ~ trials / 2^32, negligible).
_CHECK_BYTES = 4


def _check(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()[:_CHECK_BYTES]


# Frame layout (before encoding to words):
#   [0] sentinel 0x01        -- fixes byte length + validates a trial candidate
#   [1] nonce                -- varied until the decode residue is trial-able
#   [2:] whiten(body + checksum)
_SENTINEL = 0x01
_DEFAULT_KEY = b"hivemind/chatstegcipher/v1"


class ChatStegCipher:
    """Encode protocol messages as corpus-distributed chat sentences.

    Same interface as ``ChatEncoder`` (``encode(msg_type, *args) -> str`` and
    ``decode(str) -> (MessageType, [int]) | None``) so it can drop into the
    protocol in place of the plain ``HM ...`` encoder.
    """

    def __init__(self, key: bytes = _DEFAULT_KEY):
        self.key = key

    def encode(self, msg_type: MessageType, *args: int) -> str:
        m = _model()
        body = _serialize(msg_type, list(args))
        payload = body + _check(body)
        whitened = _whiten(payload, self.key)

        # A random nonce byte makes identical messages map to different
        # sentences (no repetition fingerprint). EOS suppression guarantees a
        # trial-able residue, so essentially any nonce works; loop only as a
        # defensive guard.
        for _ in range(64):
            nonce = os.urandom(1)[0]
            framed = bytes([_SENTINEL, nonce]) + whitened
            x = int.from_bytes(framed, "big")
            words, residue = _decode_int(x)
            last_ctx = (words[-1] if words else m.BOS)
            if residue < _max_eos_freq(last_ctx):
                return " ".join(m.words[w] for w in words)
        raise ValueError("could not find a steg nonce (corpus too small?)")

    def decode(self, sentence: str) -> Optional[Tuple[MessageType, List[int]]]:
        m = _model()
        tokens = sentence.split()
        if not tokens:
            return None
        word_ids: List[int] = []
        for tok in tokens:
            wid = m.word_id.get(tok)
            if wid is None:
                return None  # not all words from our vocab -> not our message
            word_ids.append(wid)

        last_ctx = (word_ids[-1] if word_ids else m.BOS)
        for residue in range(_max_eos_freq(last_ctx)):
            x = _encode_int(word_ids, residue)
            length = (x.bit_length() + 7) // 8
            if length < 3:
                continue
            framed = x.to_bytes(length, "big")
            if framed[0] != _SENTINEL:
                continue
            payload = _whiten(framed[2:], self.key)
            if len(payload) <= _CHECK_BYTES:
                continue
            body, checksum = payload[:-_CHECK_BYTES], payload[-_CHECK_BYTES:]
            if _check(body) != checksum:
                continue
            result = _deserialize(body)
            if result is not None:
                return result
        return None
