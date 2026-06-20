import asyncio
from typing import Optional

from .message_type import MessageType
from .encoder import ChatEncoder
from .dispatcher import MessageDispatcher


class HiveMindProtocol:
    """Bot-to-bot communication protocol over Wizard101 directed chat.

    Wraps a WizWalker client and provides send/receive/dispatch
    for protocol messages. The receive loop polls ChatHook exports
    for new whispers, decodes them, and dispatches to handlers.

    Usage:
        protocol = HiveMindProtocol(client)
        await protocol.start()

        # Send a ping to another bot
        await protocol.send(MessageType.PING, target_gid)

        # The receive loop auto-dispatches incoming PING -> PONG reply

        await protocol.stop()
    """

    def __init__(self, client):
        self.client = client
        self.encoder = ChatEncoder()
        self.dispatcher = MessageDispatcher()
        self._recv_task: Optional[asyncio.Task] = None
        self._last_counter = 0

        # Register default handlers
        self.dispatcher.register(MessageType.PING, self._handle_ping)
        self.dispatcher.register(MessageType.PONG, self._handle_pong)

    async def start(self):
        """Start the protocol receive loop."""
        self._recv_task = asyncio.create_task(self._receive_loop())

    async def stop(self):
        """Stop the protocol receive loop."""
        if self._recv_task:
            self._recv_task.cancel()
            try:
                await self._recv_task
            except asyncio.CancelledError:
                pass
            self._recv_task = None

    async def send(self, msg_type: MessageType, target_gid: int):
        """Send a protocol message to another bot.

        Args:
            msg_type: The message type to send
            target_gid: The target bot's GID
        """
        chat_str = self.encoder.encode(msg_type)
        await self.client.chat_owner.send_msg(chat_str, target_gid=target_gid)

    async def _receive_loop(self):
        """Poll for incoming messages and dispatch them."""
        cnt_addr = self.client.hook_handler._base_addrs.get("recv_counter")
        if cnt_addr is None:
            raise RuntimeError("ChatHook not active")

        while True:
            try:
                await asyncio.sleep(0.1)

                # Check for new message
                import struct
                counter_bytes = await self.client.hook_handler.read_bytes(cnt_addr, 8)
                counter = struct.unpack("<Q", counter_bytes)[0]

                if counter == self._last_counter:
                    continue

                self._last_counter = counter
                sender_gid, message, _ = await self.client.chat_owner.recv_message()

                # Try to decode as protocol message
                msg_type = self.encoder.decode(message.rstrip())
                if msg_type is None:
                    continue  # Not a protocol message, ignore

                print(f"[HiveMind] Received {msg_type.name} from {sender_gid}")
                await self.dispatcher.dispatch(msg_type, sender_gid)

            except asyncio.CancelledError:
                raise
            except Exception as e:
                print(f"[HiveMind] Receive error: {e}")
                await asyncio.sleep(1)

    async def _handle_ping(self, sender_gid: int):
        """Handle incoming PING: reply with PONG."""
        print(f"[HiveMind] Got PING from {sender_gid}, sending PONG")
        await self.send(MessageType.PONG, sender_gid)

    async def _handle_pong(self, sender_gid: int):
        """Handle incoming PONG: log acknowledgement."""
        print(f"[HiveMind] Got PONG from {sender_gid}, peer is alive")
