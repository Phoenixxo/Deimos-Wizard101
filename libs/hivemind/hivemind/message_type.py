from enum import Enum, auto


class MessageType(Enum):
    """Discrete protocol message types.

    Each message maps to a compact token used by the encoder. A message
    may also carry a short list of (possibly signed) integer arguments
    (see ``ChatEncoder``); the meaning of those arguments is documented
    per message type below.
    """

    # Liveness probe (legacy MVP). No arguments.
    PING = auto()
    PONG = auto()

    # Discovery handshake. Sent over DM once a peer has been spotted in
    # the entity list by its beacon yaw. Confirms that the whispering GID
    # really is the on-screen beacon (binds GID <-> entity) and exchanges
    # roles. Arguments: [role_code, qx, qy]
    #   role_code: Role.value of the sender (0 = master, 1 = slave)
    #   qx / qy: the sender's own horizontal position quantized to the
    #       shared magic grid (cell indices), so the receiver can match it
    #       against the entity it sees broadcasting the beacon yaw.
    HELLO = auto()
    HELLO_ACK = auto()

    # Bot distribution. The master offers a bot by its index into the
    # current zone's compatible-bot list (Deimos's bot_registry ordering);
    # the slave resolves that index for its own zone, prompts the user to
    # confirm, and replies accept or reject. Arguments: [bot_index]
    BOT_OFFER = auto()
    BOT_ACCEPT = auto()
    BOT_REJECT = auto()

    # Liveness. The master periodically sends KEEPALIVE to each confirmed
    # peer (proving the master is alive); the peer replies KEEPALIVE_ACK
    # (proving the slave is alive). Either side declares a peer lost when no
    # message has arrived from it within the timeout. Arguments: [seq]
    KEEPALIVE = auto()
    KEEPALIVE_ACK = auto()

    # Session lifecycle (broadcast to confirmed peers). No arguments.
    #   SESSION_PAUSE  - we are pausing execution
    #   SESSION_RESUME - we are resuming execution
    #   SESSION_END    - we are ending execution (done; stop coordinating)
    #   SESSION_LEFT   - we are leaving/disconnecting gracefully
    # END/LEFT mean the sender is no longer a participant; the receiver drops
    # it from its peer table (and releases any lock to it). A peer that
    # vanishes *without* sending these is caught by the keepalive check.
    SESSION_PAUSE = auto()
    SESSION_RESUME = auto()
    SESSION_END = auto()
    SESSION_LEFT = auto()

    # Wizard-name exchange (so the UI shows names, never GIDs). Sent in chunks
    # since a full name doesn't fit one whisper. Arguments: [part_idx, num_parts, packed]
    #   packed: a chunk of the name packed via names.pack_chunk
    NAME = auto()

    # Reserved for upcoming iterations (not yet wired up). Listed here so
    # the encoder token map and the roadmap stay in one place:
    #   KEEPALIVE_ACK = auto()  # args: [seq]
    #   SESSION_PAUSE = auto()  # lifecycle: pausing execution
    #   SESSION_RESUME = auto() # lifecycle: resuming execution
    #   SESSION_END = auto()    # lifecycle: ending execution
    #   SESSION_LEFT = auto()   # lifecycle: this client disconnected/left
