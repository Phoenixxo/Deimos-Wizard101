from __future__ import annotations

import asyncio
import struct
from contextlib import suppress
from typing import Any
import warnings

from loguru import logger

from wizwalker import HookAlreadyActivated, HookNotActive, HookNotReady, MemoryReadError
from .hooks import (
    ChatHook,
    ChatSendHook,
    ClientHook,
    MouselessCursorMoveHook,
    PlayerHook,
    PlayerStatHook,
    QuestHook,
    RootWindowHook,
    RenderContextHook,
    MovementTeleportHook,
    MemoryHook
)
from .memory_reader import MemoryReader, Primitive


# noinspection PyUnresolvedReferences
class HookHandler(MemoryReader):
    """
    Manages hooks
    """

    AUTOBOT_PATTERN = (
        rb"\x48\x8B\xC4\x55\x41\x54\x41\x55\x41\x56\x41\x57......."
        rb"\x48......\x48.......\x48\x89\x58\x10\x48\x89"
        rb"\x70\x18\x48\x89\x78\x20.......\x48\x33\xC4....."
        rb"..\x4C\x8B\xE9.......\x80......\x0F"
    )
    # rounded down
    AUTOBOT_SIZE = 3900

    def __init__(self, process: pymem.Pymem, client):
        super().__init__(process)

        self.client = client

        self._autobot_address = None
        self._autobot_lock = None
        self._original_autobot_bytes = b""
        self._autobot_pos = 0

        # TODO: Is this signature correct?
        self._active_hooks: dict[type, MemoryHook] = {}
        self._base_addrs = {}

        self._hook_cache = {}
        self._core_hook_heartbeat_task = None
        self._last_core_hook_heartbeat_error = None

    async def _get_open_autobot_address(self, size: int) -> int:
        if self._autobot_pos + size > self.AUTOBOT_SIZE:
            raise RuntimeError("Somehow went over autobot size")

        addr = self._autobot_address + self._autobot_pos
        self._autobot_pos += size

        logger.debug(
            f"Allocating autobot address {addr}; autobot position is now {self._autobot_pos}"
        )
        return addr

    async def _get_autobot_address(self):
        addr = await self.pattern_scan(
            self.AUTOBOT_PATTERN, module="WizardGraphicalClient.exe"
        )
        if addr is None:
            raise RuntimeError("Pattern scan failed for autobot pattern")

        self._autobot_address = addr

    # noinspection PyTypeChecker
    async def _prepare_autobot(self):
        if self._autobot_address is None:
            await self._get_autobot_address()

            # we only need to write back the pattern
            self._original_autobot_bytes = await self.read_bytes(
                self._autobot_address, len(self.AUTOBOT_PATTERN)
            )
            logger.debug(
                f"Got original bytes {self._original_autobot_bytes} from autobot"
            )
            await self.write_bytes(self._autobot_address, b"\x00" * self.AUTOBOT_SIZE)

    async def _rewrite_autobot(self):
        if self._autobot_address is not None:
            compare_bytes = await self.read_bytes(
                self._autobot_address, len(self.AUTOBOT_PATTERN)
            )
            # Give some time for execution point to leave hooks
            await asyncio.sleep(0.5)

            # Only write if the pattern isn't there
            if compare_bytes != self._original_autobot_bytes:
                logger.debug(
                    f"Rewriting bytes {self._original_autobot_bytes} to autobot"
                )
                await self.write_bytes(
                    self._autobot_address, self._original_autobot_bytes
                )

    async def _allocate_autobot_bytes(self, size: int) -> int:
        address = await self._get_open_autobot_address(size)

        return address

    async def close(self):
        if self._uses_agent_core_hooks():
            await self._stop_core_hook_heartbeat()
            if self._active_hooks:
                await self.run_in_executor(self._backend.deactivate_core_hooks)
            self._active_hooks = {}
            self._base_addrs = {}
            return
        for hook in self._active_hooks.values():
            await hook.unhook()

        await self._rewrite_autobot()

        self._active_hooks = {}
        self._autobot_pos = 0
        self._autobot_address = None
        self._base_addrs = {}

    async def _check_for_autobot(self):
        if self._autobot_lock is None:
            self._autobot_lock = asyncio.Lock()

        # this is so it isn't prepared more than once at the same time
        async with self._autobot_lock:
            await self._prepare_autobot()

    def _check_if_hook_active(self, hook_type) -> bool:
        return hook_type in self._active_hooks

    def _get_hook_by_type(self, hook_type) -> MemoryHook:
        return self._active_hooks.get(hook_type, None)

    def _uses_agent_core_hooks(self) -> bool:
        return bool(getattr(self._backend, "supports_core_hooks", False))

    async def _activate_agent_core_hook(
        self,
        hook_type,
        hook_name: str,
        addr_name: str,
        *,
        wait_for_ready: bool,
        timeout: float,
    ):
        await self.run_in_executor(self._backend.activate_core_hook, hook_name)
        self._active_hooks[hook_type] = hook_name
        self._base_addrs[addr_name] = hook_name
        self._ensure_core_hook_heartbeat()
        if wait_for_ready:
            await self._wait_for_core_hook(hook_name, timeout)

    async def _deactivate_agent_core_hook(self, hook_type, hook_name: str, addr_name: str):
        await self.run_in_executor(self._backend.deactivate_core_hook, hook_name)
        self._active_hooks.pop(hook_type)
        del self._base_addrs[addr_name]
        if not self._active_hooks:
            await self._stop_core_hook_heartbeat()

    def _ensure_core_hook_heartbeat(self):
        if (
            self._core_hook_heartbeat_task is None
            or self._core_hook_heartbeat_task.done()
        ):
            self._core_hook_heartbeat_task = asyncio.create_task(
                self._core_hook_heartbeat_loop()
            )

    async def _core_hook_heartbeat_loop(self):
        while True:
            await asyncio.sleep(10)
            await self._heartbeat_core_hooks_once()

    async def _heartbeat_core_hooks_once(self):
        try:
            await self.run_in_executor(self._backend.heartbeat_core_hooks)
        except asyncio.CancelledError:
            raise
        except Exception as error:
            self._last_core_hook_heartbeat_error = error
        else:
            self._last_core_hook_heartbeat_error = None

    async def _stop_core_hook_heartbeat(self):
        task = self._core_hook_heartbeat_task
        self._core_hook_heartbeat_task = None
        if task is None:
            return
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task

    def cancel_core_hook_heartbeat(self):
        task = self._core_hook_heartbeat_task
        self._core_hook_heartbeat_task = None
        if task is not None:
            task.cancel()

    async def _read_hook_base_addr(self, addr_name: str, hook_name: str):
        addr = self._base_addrs.get(addr_name)
        if addr is None:
            raise HookNotActive(hook_name)
        if self._uses_agent_core_hooks():
            value = await self.run_in_executor(
                self._backend.read_core_hook_base, addr
            )
            if value == 0:
                raise HookNotReady(hook_name)
            return value

        try:
            return await self.read_typed(addr, Primitive.int64)
        except MemoryReadError as error:
            raise HookNotReady(hook_name) from error

    async def _wait_for_core_hook(self, hook_name: str, timeout: float = None):
        async def _wait():
            while True:
                value = await self.run_in_executor(
                    self._backend.read_core_hook_base, hook_name
                )
                if value != 0:
                    return
                await asyncio.sleep(0.5)

        try:
            await asyncio.wait_for(_wait(), timeout)
        except asyncio.TimeoutError as error:
            raise TimeoutError("Hook value took too long") from error

    # wait for an addr to be set and not 0
    async def _wait_for_value(self, address: int, timeout: int = None):
        async def _wait_for_value_task():
            while True:
                try:
                    value = await self.read_typed(address, Primitive.int64)
                    logger.debug(
                        f"Waiting for address {hex(address)}; got value {value}"
                    )
                except MemoryReadError:
                    pass
                else:
                    if value != 0:
                        logger.debug(f"Address {hex(address)} is set")
                        break
                    else:
                        logger.debug(f"Address {hex(address)} is not set yet; sleeping")
                        await asyncio.sleep(0.5)

        try:
            await asyncio.wait_for(_wait_for_value_task(), timeout)
        except asyncio.TimeoutError as error:
            raise TimeoutError("Hook value took too long") from error

    # TODO: make this faster
    async def activate_all_hooks(
        self, *, wait_for_ready: bool = True, timeout: float = None
    ):
        """
        Activate all hooks but mouseless

        Keyword Args:
            wait_for_ready: Wait for hook values to be written
            timeout: How long to wait for hook values to be written (None for no timeout)
        """
        if self._uses_agent_core_hooks():
            if self._active_hooks:
                duplicate = next(iter(self._active_hooks))
                raise HookAlreadyActivated(duplicate.__name__.removesuffix("Hook"))
            await self.run_in_executor(self._backend.activate_core_hooks)
            mappings = (
                (PlayerHook, "player", "player_struct"),
                (QuestHook, "quest", "quest_struct"),
                (PlayerStatHook, "player_stat", "player_stat_struct"),
                (ClientHook, "client", "current_client"),
                (RootWindowHook, "root_window", "current_root_window"),
                (RenderContextHook, "render_context", "current_render_context"),
            )
            for hook_type, hook_name, addr_name in mappings:
                self._active_hooks[hook_type] = hook_name
                self._base_addrs[addr_name] = hook_name
            self._ensure_core_hook_heartbeat()
            if wait_for_ready:
                await asyncio.gather(
                    *(
                        self._wait_for_core_hook(hook_name, timeout)
                        for hook_name in (
                            "player",
                            "player_stat",
                            "client",
                            "root_window",
                            "render_context",
                        )
                    )
                )
            return
        await self.activate_player_hook(wait_for_ready=False)
        # quest hook is not written if the quest arrow is off
        await self.activate_quest_hook()
        await self.activate_player_stat_hook(wait_for_ready=False)
        await self.activate_client_hook(wait_for_ready=False)
        await self.activate_root_window_hook(wait_for_ready=False)
        await self.activate_render_context_hook(wait_for_ready=False)
        await self.activate_movement_teleport_hook(wait_for_ready=False)

        if wait_for_ready:
            wait_tasks = []
            for atter_name in [
                "player_struct",
                "player_stat_struct",
                "current_client",
                "current_root_window",
                "current_render_context",
            ]:
                value = self._base_addrs[atter_name]
                wait_tasks.append(
                    asyncio.create_task(self._wait_for_value(value, timeout))
                )

            await asyncio.gather(*wait_tasks)

    async def activate_player_hook(
        self, *, wait_for_ready: bool = True, timeout: float = None
    ):
        """
        Activate player hook

        Keyword Args:
            wait_for_ready: Wait for hook values to be written
            timeout: How long to wait for hook values to be written (None for no timeout)
        """
        if self._check_if_hook_active(PlayerHook):
            raise HookAlreadyActivated("Player")
        if self._uses_agent_core_hooks():
            return await self._activate_agent_core_hook(
                PlayerHook,
                "player",
                "player_struct",
                wait_for_ready=wait_for_ready,
                timeout=timeout,
            )

        await self._check_for_autobot()

        player_hook = PlayerHook(self)
        await player_hook.hook()

        self._active_hooks[PlayerHook] = player_hook
        self._base_addrs["player_struct"] = player_hook.player_struct

        if wait_for_ready:
            await self._wait_for_value(player_hook.player_struct, timeout)

    async def deactivate_player_hook(self):
        """
        Deactivate player hook
        """
        if not self._check_if_hook_active(PlayerHook):
            raise HookNotActive("Player")
        if self._uses_agent_core_hooks():
            return await self._deactivate_agent_core_hook(
                PlayerHook, "player", "player_struct"
            )

        hook = self._active_hooks.pop(PlayerHook)
        await hook.unhook()

        del self._base_addrs["player_struct"]

    async def read_current_player_base(self) -> int:
        """
        Read player base address

        Returns:
            The player base address
        """
        return await self._read_hook_base_addr("player_struct", "Player")

    async def activate_quest_hook(
        self, *, wait_for_ready: bool = False, timeout: float = None
    ):
        """
        Activate quest hook

        Keyword Args:
            wait_for_ready: Wait for hook values to be written
            timeout: How long to wait for hook values to be written (None for no timeout)
        """
        if self._check_if_hook_active(QuestHook):
            raise HookAlreadyActivated("Quest")
        if self._uses_agent_core_hooks():
            return await self._activate_agent_core_hook(
                QuestHook,
                "quest",
                "quest_struct",
                wait_for_ready=wait_for_ready,
                timeout=timeout,
            )

        await self._check_for_autobot()

        quest_hook = QuestHook(self)
        await quest_hook.hook()

        self._active_hooks[QuestHook] = quest_hook
        self._base_addrs["quest_struct"] = quest_hook.cord_struct

        if wait_for_ready:
            await self._wait_for_value(quest_hook.cord_struct, timeout)

    async def deactivate_quest_hook(self):
        """
        Deactivate quest hook
        """
        if not self._check_if_hook_active(QuestHook):
            raise HookNotActive("Quest")
        if self._uses_agent_core_hooks():
            return await self._deactivate_agent_core_hook(
                QuestHook, "quest", "quest_struct"
            )

        hook = self._active_hooks.pop(QuestHook)
        await hook.unhook()

        del self._base_addrs["quest_struct"]

    async def read_current_quest_base(self) -> int:
        """
        Read quest base address

        Returns:
            The quest base address
        """
        return await self._read_hook_base_addr("quest_struct", "Quest")

    async def activate_player_stat_hook(
        self, *, wait_for_ready: bool = True, timeout: float = None
    ):
        """
        Activate player stat hook

        Keyword Args:
            wait_for_ready: Wait for hook values to be written
            timeout: How long to wait for hook values to be written (None for no timeout)
        """
        if self._check_if_hook_active(PlayerStatHook):
            raise HookAlreadyActivated("Player stat")
        if self._uses_agent_core_hooks():
            return await self._activate_agent_core_hook(
                PlayerStatHook,
                "player_stat",
                "player_stat_struct",
                wait_for_ready=wait_for_ready,
                timeout=timeout,
            )

        await self._check_for_autobot()

        player_stat_hook = PlayerStatHook(self)
        await player_stat_hook.hook()

        self._active_hooks[PlayerStatHook] = player_stat_hook
        self._base_addrs["player_stat_struct"] = player_stat_hook.stat_addr

        if wait_for_ready:
            await self._wait_for_value(player_stat_hook.stat_addr, timeout)

    async def deactivate_player_stat_hook(self):
        """
        Deactivate player stat hook
        """
        if not self._check_if_hook_active(PlayerStatHook):
            raise HookNotActive("Player stat")
        if self._uses_agent_core_hooks():
            return await self._deactivate_agent_core_hook(
                PlayerStatHook, "player_stat", "player_stat_struct"
            )

        hook = self._active_hooks.pop(PlayerStatHook)
        await hook.unhook()

        del self._base_addrs["player_stat_struct"]

    async def read_current_player_stat_base(self) -> int:
        """
        Read player stat base address

        Returns:
            The player stat base address
        """
        return await self._read_hook_base_addr("player_stat_struct", "Player stat")

    async def activate_client_hook(
        self, *, wait_for_ready: bool = True, timeout: float = None
    ):
        """
        Activate client hook

        Keyword Args:
            wait_for_ready: Wait for hook values to be written
            timeout: How long to wait for hook values to be written (None for no timeout)
        """
        if self._check_if_hook_active(ClientHook):
            raise HookAlreadyActivated("Client")
        if self._uses_agent_core_hooks():
            return await self._activate_agent_core_hook(
                ClientHook,
                "client",
                "current_client",
                wait_for_ready=wait_for_ready,
                timeout=timeout,
            )

        await self._check_for_autobot()

        client_hook = ClientHook(self)
        await client_hook.hook()

        self._active_hooks[ClientHook] = client_hook
        self._base_addrs["current_client"] = client_hook.current_client_addr

        if wait_for_ready:
            await self._wait_for_value(client_hook.current_client_addr, timeout)

    async def deactivate_client_hook(self):
        """
        Deactivate client hook
        """
        if not self._check_if_hook_active(ClientHook):
            raise HookNotActive("Client")
        if self._uses_agent_core_hooks():
            return await self._deactivate_agent_core_hook(
                ClientHook, "client", "current_client"
            )

        hook = self._active_hooks.pop(ClientHook)
        await hook.unhook()

        del self._base_addrs["current_client"]

    async def read_current_client_base(self) -> int:
        """
        Read cureent client base address

        Returns:
            The current client base address
        """
        return await self._read_hook_base_addr("current_client", "Client")

    async def activate_root_window_hook(
        self, *, wait_for_ready: bool = True, timeout: float = None
    ):
        """
        Activate root window hook

        Keyword Args:
            wait_for_ready: Wait for hook values to be written
            timeout: How long to wait for hook values to be written (None for no timeout)
        """
        if self._check_if_hook_active(RootWindowHook):
            raise HookAlreadyActivated("Root window")
        if self._uses_agent_core_hooks():
            return await self._activate_agent_core_hook(
                RootWindowHook,
                "root_window",
                "current_root_window",
                wait_for_ready=wait_for_ready,
                timeout=timeout,
            )

        await self._check_for_autobot()

        root_window_hook = RootWindowHook(self)
        await root_window_hook.hook()

        self._active_hooks[RootWindowHook] = root_window_hook
        self._base_addrs[
            "current_root_window"
        ] = root_window_hook.current_root_window_addr

        if wait_for_ready:
            await self._wait_for_value(
                root_window_hook.current_root_window_addr, timeout
            )

    async def deactivate_root_window_hook(self):
        """
        Deactivate root window hook
        """
        if not self._check_if_hook_active(RootWindowHook):
            raise HookNotActive("Root window")
        if self._uses_agent_core_hooks():
            return await self._deactivate_agent_core_hook(
                RootWindowHook, "root_window", "current_root_window"
            )

        hook = self._active_hooks.pop(RootWindowHook)
        await hook.unhook()

        del self._base_addrs["current_root_window"]

    async def read_current_root_window_base(self) -> int:
        """
        Read current root window base address

        Returns:
            The current root window base address
        """
        return await self._read_hook_base_addr("current_root_window", "Root window")

    async def activate_render_context_hook(
        self, *, wait_for_ready: bool = True, timeout: float = None
    ):
        """
        Activate render context hook

        Keyword Args:
            wait_for_ready: Wait for hook values to be written
            timeout: How long to wait for hook values to be written (None for no timeout)
        """
        if self._check_if_hook_active(RenderContextHook):
            raise HookAlreadyActivated("Render context")
        if self._uses_agent_core_hooks():
            return await self._activate_agent_core_hook(
                RenderContextHook,
                "render_context",
                "current_render_context",
                wait_for_ready=wait_for_ready,
                timeout=timeout,
            )

        await self._check_for_autobot()

        render_context_hook = RenderContextHook(self)
        await render_context_hook.hook()

        self._active_hooks[RenderContextHook] = render_context_hook
        self._base_addrs[
            "current_render_context"
        ] = render_context_hook.current_render_context_addr

        if wait_for_ready:
            await self._wait_for_value(
                render_context_hook.current_render_context_addr, timeout
            )

    async def deactivate_render_context_hook(self):
        """
        Deactivate render context hook
        """
        if not self._check_if_hook_active(RenderContextHook):
            raise HookNotActive("Render context")
        if self._uses_agent_core_hooks():
            return await self._deactivate_agent_core_hook(
                RenderContextHook, "render_context", "current_render_context"
            )

        hook = self._active_hooks.pop(RenderContextHook)
        await hook.unhook()

        del self._base_addrs["current_render_context"]

    async def read_current_render_context_base(self) -> int:
        """
        Read current render context base address

        Returns:
            The current render context base address
        """
        return await self._read_hook_base_addr(
            "current_render_context", "Render context"
        )

    async def activate_movement_teleport_hook(
            self, *, wait_for_ready: bool = False, timeout: float = None
    ):
        """
        Activate movement teleport hook

        wait_for_ready is useless for this hook

        Keyword Args:
            wait_for_ready: Wait for hook values to be written
            timeout: How long to wait for hook values to be written (None for no timeout)
        """
        if self._check_if_hook_active(MovementTeleportHook):
            raise HookAlreadyActivated("Movement teleport")

        await self._check_for_autobot()

        movement_teleport_hook = MovementTeleportHook(self)
        await movement_teleport_hook.hook()

        self._active_hooks[MovementTeleportHook] = movement_teleport_hook
        self._base_addrs[
            "teleport_helper"
        ] = movement_teleport_hook.teleport_helper

    async def deactivate_movement_teleport_hook(self):
        """
        Deactivate movement teleport hook
        """
        if not self._check_if_hook_active(MovementTeleportHook):
            raise HookNotActive("Movement teleport")

        hook = self._active_hooks.pop(MovementTeleportHook)
        await hook.unhook()

        del self._base_addrs["teleport_helper"]

    async def read_teleport_helper(self) -> int:
        """
        Read teleport helper base address

        Returns:
            The teleport helper base address
        """
        addr = self._base_addrs.get("teleport_helper")
        if addr is None:
            raise HookNotActive("Movement teleport")

        return addr

    # nothing to wait for in this hook
    async def activate_mouseless_cursor_hook(self):
        """
        Activate mouseless cursor hook
        """
        if self._check_if_hook_active(MouselessCursorMoveHook):
            raise HookAlreadyActivated("Mouseless cursor")

        await self._check_for_autobot()

        mouseless_cursor_hook = MouselessCursorMoveHook(self, self._hook_cache)
        await mouseless_cursor_hook.hook()

        self._active_hooks[MouselessCursorMoveHook] = mouseless_cursor_hook
        self._base_addrs["mouse_position"] = mouseless_cursor_hook.mouse_pos_addr

        await self.write_mouse_position(0, 0)

    async def deactivate_mouseless_cursor_hook(self):
        """
        Deactivate mouseless cursor hook
        """
        if not self._check_if_hook_active(MouselessCursorMoveHook):
            raise HookNotActive("Mouseless cursor")

        hook = self._active_hooks.pop(MouselessCursorMoveHook)
        await hook.unhook()

        del self._base_addrs["mouse_position"]

    # TODO: 2.0 switch this to a helper object like movement teleport and quest
    async def write_mouse_position(self, x: int, y: int):
        """
        Write mouse position to memory

        Args:
            x: x position of mouse
            y: y position of mouse
        """
        addr = self._base_addrs.get("mouse_position")
        if addr is None:
            raise HookNotActive("Mouseless cursor")

        packed_position = struct.pack("<ii", x, y)

        await self.write_bytes(addr, packed_position)

    async def activate_chat_hook(
        self, *, wait_for_ready: bool = True, timeout: float = None
    ):
        """Activate the chat hook to capture incoming directed chat messages.

        The hook fires on every incoming MSG_DirectedChat, extracting the
        sender's GID and message text to persistent export buffers.

        Keyword Args:
            wait_for_ready: Wait for the first message to arrive
            timeout: How long to wait (None for no timeout)
        """
        if self._check_if_hook_active(ChatHook):
            raise HookAlreadyActivated("Chat")

        await self._check_for_autobot()

        chat_hook = ChatHook(self)
        await chat_hook.hook()

        self._active_hooks[ChatHook] = chat_hook
        self._base_addrs["chat_owner"] = chat_hook.chat_owner_addr
        self._base_addrs["recv_source_gid"] = chat_hook.recv_source_gid
        self._base_addrs["recv_message_buf"] = chat_hook.recv_message_buf
        self._base_addrs["recv_message_len"] = chat_hook.recv_message_len
        self._base_addrs["recv_counter"] = chat_hook.recv_counter

        if wait_for_ready:
            await self._wait_for_value(chat_hook.recv_counter, timeout)

    async def deactivate_chat_hook(self):
        """Deactivate the chat hook."""
        if not self._check_if_hook_active(ChatHook):
            raise HookNotActive("Chat")

        hook = self._active_hooks.pop(ChatHook)
        await hook.unhook()

        del self._base_addrs["chat_owner"]
        del self._base_addrs["recv_source_gid"]
        del self._base_addrs["recv_message_buf"]
        del self._base_addrs["recv_message_len"]
        del self._base_addrs["recv_counter"]

    async def read_chat_owner_base(self) -> int:
        """Read the chat owner (chat module) base address.

        Returns:
            The chat module base address
        """
        return await self._read_hook_base_addr("chat_owner", "Chat")

    async def activate_chat_send_hook(self):
        """Activate the chat send hook on the main game loop.

        This hooks the game's main loop so that send_msg() executes
        on the main thread where chat operations are safe.
        """
        if self._check_if_hook_active(ChatSendHook):
            raise HookAlreadyActivated("Chat send")

        await self._check_for_autobot()

        hook = ChatSendHook(self)
        await hook.hook()

        self._active_hooks[ChatSendHook] = hook
        self._base_addrs["send_trigger"] = hook.send_trigger
        self._base_addrs["send_struct"] = hook.send_struct
        self._base_addrs["buddy_trigger"] = hook.buddy_trigger
        self._base_addrs["buddy_obj"] = hook.buddy_obj

    async def deactivate_chat_send_hook(self):
        """Deactivate the chat send hook."""
        if not self._check_if_hook_active(ChatSendHook):
            raise HookNotActive("Chat send")

        hook = self._active_hooks.pop(ChatSendHook)
        await hook.unhook()

        del self._base_addrs["send_trigger"]
        del self._base_addrs["send_struct"]
        del self._base_addrs["buddy_trigger"]
        del self._base_addrs["buddy_obj"]
