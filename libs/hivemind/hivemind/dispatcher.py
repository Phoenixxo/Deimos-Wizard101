from typing import Awaitable, Callable, Dict, List

from .message_type import MessageType


# Handler signature: async fn(sender_gid: int, args: List[int]) -> None
HandlerFn = Callable[[int, List[int]], Awaitable[None]]


class MessageDispatcher:
    """Routes decoded MessageTypes to registered handler functions.

    Each MessageType maps to exactly one async handler. When a
    protocol message arrives, dispatch() calls the corresponding
    handler with the sender's GID and the message's integer arguments.
    """

    def __init__(self):
        self._handlers: Dict[MessageType, HandlerFn] = {}

    def register(self, msg_type: MessageType, handler: HandlerFn):
        """Register a handler for a message type.

        Args:
            msg_type: The message type to handle
            handler: Async function called with (sender_gid, args)
        """
        self._handlers[msg_type] = handler

    async def dispatch(self, msg_type: MessageType, sender_gid: int, args: List[int]):
        """Dispatch a decoded message to its handler.

        Args:
            msg_type: The decoded message type
            sender_gid: GID of the player who sent the message
            args: The message's decoded integer arguments

        Returns:
            True if a handler was found and called, False otherwise
        """
        handler = self._handlers.get(msg_type)
        if handler is None:
            return False
        await handler(sender_gid, args)
        return True
