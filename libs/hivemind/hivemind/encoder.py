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
}

_REVERSE_MAP = {v: k for k, v in _TOKEN_MAP.items()}

# Protocol prefix to distinguish HiveMind messages from normal chat.
# Must use only characters the game's chat filter allows (alphanumeric
# and spaces no colons, symbols, or punctuation). Otherwise you get 
# emojis depending on the context. e.g -> HM P0 -> :P is emoji
_PROTOCOL_PREFIX = "HM "


class ChatEncoder:
    """Maps MessageType enums to/from wire-format chat strings.

    MVP: produces simple prefixed tokens like "HM P0" for PING.
    Post-MVP: ChatStegCipher will sit between this and the wire,
    transforming tokens into natural chat sentences.
    """

    def encode(self, msg_type: MessageType) -> str:
        """Encode a MessageType to a chat string for sending.

        Args:
            msg_type: The protocol message to encode

        Returns:
            A chat string ready for send_msg()
        """
        token = _TOKEN_MAP.get(msg_type)
        if token is None:
            raise ValueError(f"No token mapping for {msg_type}")
        return f"{_PROTOCOL_PREFIX}{token}"

    def decode(self, chat_str: str) -> MessageType | None:
        """Decode a chat string to a MessageType.

        Args:
            chat_str: Raw chat message text

        Returns:
            The decoded MessageType, or None if not a protocol message
        """
        if not chat_str.startswith(_PROTOCOL_PREFIX):
            return None
        token = chat_str[len(_PROTOCOL_PREFIX):]
        return _REVERSE_MAP.get(token)
