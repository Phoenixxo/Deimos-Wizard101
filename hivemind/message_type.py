from enum import Enum, auto


class MessageType(Enum):
    """Discrete protocol message types.

    Each message maps to a compact token used by the encoder.
    MVP: PING/PONG only. Future messages extend this enum.
    """
    PING = auto()
    PONG = auto()

    # Future protocol messages (not in MVP):
    # QUERY_FREE = auto()
    # REPLY_FREE_YES = auto()
    # REPLY_FREE_NO = auto()
    # QUERY_HELP = auto()
    # REPLY_HELP_YES = auto()
    # REPLY_HELP_NO = auto()
    # PROPOSE_FARM = auto()
    # REPLY_FARM_YES = auto()
    # REPLY_FARM_NO = auto()
    # ANNOUNCE_REALM = auto()
    # CONFIRM_REALM = auto()
    # ANNOUNCE_ZONE = auto()
    # CONFIRM_ZONE = auto()
    # PROPOSE_MEETUP = auto()
    # KEEPALIVE = auto()
