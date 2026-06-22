from .message_type import MessageType


# Compact token map: MessageType <-> short string token.
# These tokens are the internal representation before the
# steganography layer (ChatStegCipher, post-MVP) transforms
# them into natural-looking chat strings.
#
# For the MVP, tokens are sent as-is over the wire. The
# ChatStegCipher layer will be inserted between encode/decode
# and the actual send/recv to make messages look like normal chat.
_TOKEN_MAP = {
    MessageType.PING: "P0",
    MessageType.PONG: "P1",
    MessageType.HELLO: "H0",
    MessageType.HELLO_ACK: "H1",
    MessageType.BOT_OFFER: "B0",
    MessageType.BOT_ACCEPT: "B1",
    MessageType.BOT_REJECT: "B2",
    MessageType.KEEPALIVE: "K0",
    MessageType.KEEPALIVE_ACK: "K1",
    MessageType.SESSION_PAUSE: "S0",
    MessageType.SESSION_RESUME: "S1",
    MessageType.SESSION_END: "S2",
    MessageType.SESSION_LEFT: "S3",
    MessageType.NAME: "N0",
}

_REVERSE_MAP = {v: k for k, v in _TOKEN_MAP.items()}

# Protocol prefix to distinguish HiveMind messages from normal chat.
# Must use only characters the game's chat filter allows (alphanumeric
# and spaces, no colons, symbols, or punctuation). Otherwise you get
# emojis depending on the context. e.g -> HM P0 -> :P is emoji
_PROTOCOL_PREFIX = "HM "

# The game relays at most 79 wchars to the other client (see
# ChatOwner.send_msg). Encoded messages must stay under that.
_MAX_MESSAGE_CHARS = 79

# Arguments are encoded as base-36 (0-9a-z) so the whole message stays
# alphanumeric. Signed integers (e.g. negative world coordinates) are
# zig-zag mapped to non-negative ints first.
_B36_ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyz"


def _zigzag_encode(n: int) -> int:
    return (2 * n) if n >= 0 else (-2 * n - 1)


def _zigzag_decode(u: int) -> int:
    return (u >> 1) if (u & 1) == 0 else -((u + 1) >> 1)


def _to_b36(u: int) -> str:
    if u == 0:
        return "0"
    out = []
    while u:
        u, rem = divmod(u, 36)
        out.append(_B36_ALPHABET[rem])
    return "".join(reversed(out))


def encode_int(n: int) -> str:
    """Encode a signed integer to a compact alphanumeric token."""
    return _to_b36(_zigzag_encode(n))


def decode_int(token: str) -> int:
    """Inverse of ``encode_int``. Raises ValueError on malformed input."""
    return _zigzag_decode(int(token, 36))


class ChatEncoder:
    """Maps protocol messages to/from wire-format chat strings.

    A message is a ``MessageType`` plus zero or more integer arguments.
    It is encoded as ``"HM <token> <arg> <arg> ..."`` where the token
    identifies the type and each argument is base-36 (so the whole
    string is alphanumeric + spaces, which the chat filter accepts).

    Post-MVP: ChatStegCipher will sit between this and the wire,
    transforming tokens into natural chat sentences.
    """

    def encode(self, msg_type: MessageType, *args: int) -> str:
        """Encode a message (type + integer args) to a chat string.

        Args:
            msg_type: The protocol message to encode
            *args: Signed integer arguments for the message

        Returns:
            A chat string ready for send_msg()

        Raises:
            ValueError: If the type has no token or the result is too long
        """
        token = _TOKEN_MAP.get(msg_type)
        if token is None:
            raise ValueError(f"No token mapping for {msg_type}")

        parts = [token]
        parts.extend(encode_int(a) for a in args)
        chat_str = _PROTOCOL_PREFIX + " ".join(parts)

        if len(chat_str) > _MAX_MESSAGE_CHARS:
            raise ValueError(
                f"Encoded message too long ({len(chat_str)} > {_MAX_MESSAGE_CHARS}): "
                f"{msg_type.name} with {len(args)} args"
            )
        return chat_str

    def decode(self, chat_str: str) -> tuple[MessageType, list[int]] | None:
        """Decode a chat string to a (MessageType, args) pair.

        Args:
            chat_str: Raw chat message text

        Returns:
            A ``(MessageType, [int, ...])`` tuple, or None if the string
            is not a well-formed protocol message.
        """
        if not chat_str.startswith(_PROTOCOL_PREFIX):
            return None

        fields = chat_str[len(_PROTOCOL_PREFIX):].split()
        if not fields:
            return None

        msg_type = _REVERSE_MAP.get(fields[0])
        if msg_type is None:
            return None

        try:
            args = [decode_int(f) for f in fields[1:]]
        except ValueError:
            return None  # garbled args -> treat as non-protocol chat

        return msg_type, args
