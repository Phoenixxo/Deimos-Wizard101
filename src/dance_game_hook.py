import asyncio

from wizwalker import (
    Client,
    HookAlreadyActivated,
    HookNotActive,
    HookNotReady,
    await_cleanup_preserving_cancellation,
)
from wizwalker.memory import HookHandler, SimpleHook

from loguru import logger
import traceback

_dance_moves_transtable = str.maketrans("abcd", "WDSA")

# Thanks to peechez for this class
class DanceGameMovesHook(SimpleHook):
    pattern = rb"\x48\x8B\xD8\x48\x39\x70\x10\x76.\x8B\xC6"
    instruction_length = 7
    exports = [("dance_game_moves", 8)]
    noops = 2

    async def bytecode_generator(self, packed_exports):
        return (
                b"\x48\x8B\xD8"
                b"\x48\x8B\x00"
                b"\x48\xA3" + packed_exports[0][1] +
                b"\x48\x8B\xC3"
                b"\x48\x39\x70\x10"
        )



async def activate_dance_game_moves_hook(
        self, *, wait_for_ready: bool = False, timeout: float = None
):
    if self._check_if_hook_active(DanceGameMovesHook):
        raise HookAlreadyActivated("DanceGameMovesHook")

    if self._uses_agent_feature_hooks():
        await self._activate_agent_feature_hook(
            DanceGameMovesHook,
            "dance_game_moves",
            {"dance_game_moves": "dance_game_moves"},
            initialize=(
                lambda: self._wait_for_value(
                    self._base_addrs["dance_game_moves"], timeout
                )
            ) if wait_for_ready else None,
        )
        return

    await self._check_for_autobot()

    hook = DanceGameMovesHook(self)
    await self._activate_legacy_hook(
        DanceGameMovesHook,
        hook,
        {"dance_game_moves": "dance_game_moves"},
        initialize=(
            lambda: self._wait_for_value(hook.dance_game_moves, timeout)
        ) if wait_for_ready else None,
    )


async def serialized_activate_dance_game_moves_hook(self, *args, **kwargs):
    async with self._close_lock:
        self._ensure_hook_activation_allowed()
        try:
            return await activate_dance_game_moves_hook(self, *args, **kwargs)
        except BaseException as activation_error:
            if not isinstance(activation_error, Exception):
                await await_cleanup_preserving_cancellation(
                    self._rollback_unused_legacy_storage(),
                    activation_error,
                    operation="dance game hook legacy storage rollback",
                )
            raise


HookHandler.activate_dance_game_moves_hook = serialized_activate_dance_game_moves_hook


async def deactivate_dance_game_moves_hook(self):
    if not self._check_if_hook_active(DanceGameMovesHook):
        raise HookNotActive("DanceGameMovesHook")

    if self._uses_agent_feature_hooks():
        return await self._deactivate_agent_feature_hook(
            DanceGameMovesHook,
            "dance_game_moves",
            ("dance_game_moves",),
        )

    await self._deactivate_legacy_hook(
        DanceGameMovesHook, ("dance_game_moves",)
    )


async def serialized_deactivate_dance_game_moves_hook(self, *args, **kwargs):
    async with self._close_lock:
        return await deactivate_dance_game_moves_hook(self, *args, **kwargs)


HookHandler.deactivate_dance_game_moves_hook = serialized_deactivate_dance_game_moves_hook

async def attempt_activate_dance_hook(client: Client, sleep_time: float = 0.1):
    # Attempts to activate dance hook, in a try block in case it's already off for this client
    if not client.dance_hook_status:
        try:
            await client.hook_handler.activate_dance_game_moves_hook()
        except Exception:
            logger.debug("failed to activate dance hook")
            logger.debug(traceback.print_exc())
            pass

        client.dance_hook_status = True
    await asyncio.sleep(sleep_time)

async def attempt_deactivate_dance_hook(client: Client, sleep_time: float = 0.1):
    # Attempts to deactivate dance hook, in a try block in case it's already off for this client
    if client.dance_hook_status:
        try:
            await client.hook_handler.deactivate_dance_game_moves_hook()
        except Exception:
            pass

        client.dance_hook_status = False
    await asyncio.sleep(sleep_time)


async def read_current_dance_game_moves(self) -> str:
    try:
        addr = self._base_addrs["dance_game_moves"]
    except KeyError:
        raise HookNotActive("DanceGameMovesHook")

    if self._uses_agent_feature_hooks():
        addr = await self._read_feature_hook_export(
            "dance_game_moves", "DanceGameMovesHook"
        )
    try:
        moves = await self.read_bytes(addr, 8)
    except Exception as error:
        if self._backend.is_read_error(error):
            raise HookNotReady("DanceGameMovesHook") from error
        raise
    return moves.partition(b"\0")[0].decode().translate(_dance_moves_transtable)


HookHandler.read_current_dance_game_moves = read_current_dance_game_moves
