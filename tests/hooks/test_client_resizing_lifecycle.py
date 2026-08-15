from __future__ import annotations

import asyncio
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from wizwalker.extensions.wizsprinter.resolution_hook import (
    ResolutionForcer,
    SetModeResHook,
    WindowResizeBorder,
    WndProcNCHitHook,
)
from wizwalker.memory.hooks import MemoryHook

from src.client_resizing import ClientResizingManager


class ClientResizingLifecycleTests(unittest.IsolatedAsyncioTestCase):
    @staticmethod
    def _pre_jump_failure_hook(handler):
        class PreJumpFailureHook(MemoryHook):
            async def get_pattern(self):
                return b"pattern", None

            async def get_jump_address(self, pattern, module=None):
                return 0x1000

            async def get_hook_address(self, size):
                self._allocated_addresses.append(0x2000)
                return 0x2000

            async def get_hook_bytecode(self):
                raise RuntimeError("Keystone assembly failed")

        hook = PreJumpFailureHook(handler)
        hook.free = AsyncMock()
        hook.write_bytes = AsyncMock()
        return hook

    async def test_pre_jump_hook_failure_frees_allocation_without_restoring_bytes(self):
        hook = self._pre_jump_failure_hook(SimpleNamespace(process=object()))

        with self.assertRaisesRegex(RuntimeError, "Keystone assembly failed"):
            await hook.hook()
        await hook.unhook()
        await hook.unhook()

        hook.write_bytes.assert_not_awaited()
        hook.free.assert_awaited_once_with(0x2000)
        self.assertEqual(hook._allocated_addresses, [])

    async def test_failed_target_jump_write_restores_before_freeing_allocation(self):
        class TargetWriteFailureHook(MemoryHook):
            async def get_pattern(self):
                return b"pattern", None

            async def get_jump_address(self, pattern, module=None):
                return 0x1000

            async def get_hook_address(self, size):
                self._allocated_addresses.append(0x2000)
                return 0x2000

            async def get_hook_bytecode(self):
                return b"hook"

            async def get_jump_bytecode(self):
                return b"jump"

        events = []
        hook = TargetWriteFailureHook(SimpleNamespace(process=object()))
        hook.read_bytes = AsyncMock(return_value=b"orig")

        async def write(address, value):
            events.append(("write", address, value))
            if address == 0x1000 and value == b"jump":
                raise RuntimeError("target write failed")

        async def free(address):
            events.append(("free", address))

        hook.write_bytes = write
        hook.free = free

        with self.assertRaisesRegex(RuntimeError, "target write failed"):
            await hook.hook()
        self.assertTrue(hook._jump_write_started)

        await hook.unhook()

        self.assertFalse(hook._jump_write_started)
        self.assertEqual(
            events[-2:],
            [("write", 0x1000, b"orig"), ("free", 0x2000)],
        )
        self.assertEqual(hook._allocated_addresses, [])

    async def test_resolution_forcer_clears_pre_jump_failure_after_cleanup(self):
        handler = SimpleNamespace(
            process=SimpleNamespace(allocate=lambda size: 0x3000),
            _check_for_autobot=AsyncMock(),
            _allocate_autobot_bytes=AsyncMock(return_value=0x2000),
        )
        hook = SetModeResHook(handler)
        hook.get_jump_address = AsyncMock(return_value=0x1000)
        hook.bytecode_generator = AsyncMock(
            side_effect=RuntimeError("Keystone assembly failed")
        )
        hook.free = AsyncMock()
        hook.write_bytes = AsyncMock()
        forcer = ResolutionForcer(SimpleNamespace(hook_handler=handler))

        with patch(
            "wizwalker.extensions.wizsprinter.resolution_hook.SetModeResHook",
            return_value=hook,
        ):
            with self.assertRaisesRegex(RuntimeError, "Keystone assembly failed"):
                await forcer.install()

        self.assertFalse(forcer.installed)
        self.assertIsNone(forcer._setmode)
        self.assertIsNone(forcer._vm)
        hook.write_bytes.assert_not_awaited()
        hook.free.assert_awaited_once_with(0x3000)

    async def test_keystone_failure_cleans_border_without_restoring_jump(self):
        class Process:
            def __init__(self):
                self.freed = []
                self.writes = []

            def allocate(self, size):
                return 0x3000

            def free(self, address):
                self.freed.append(address)

            def write_bytes(self, address, value, size):
                self.writes.append((address, value, size))

        process = Process()
        handler = SimpleNamespace(
            process=process,
            _check_for_autobot=AsyncMock(),
            _allocate_autobot_bytes=AsyncMock(return_value=0x2000),
        )
        border = WindowResizeBorder(SimpleNamespace(hook_handler=handler))

        with (
            patch.object(
                WndProcNCHitHook,
                "get_jump_address",
                new=AsyncMock(return_value=0x1000),
            ),
            patch(
                "wizwalker.extensions.wizsprinter.resolution_hook._assemble",
                side_effect=RuntimeError("Keystone assembly failed"),
            ),
        ):
            with self.assertRaisesRegex(RuntimeError, "Keystone assembly failed"):
                await border.install()

        self.assertFalse(border.installed)
        self.assertEqual(process.freed, [0x3000])
        self.assertEqual(process.writes, [])

    def test_second_partial_hook_counts_as_installed(self):
        forcer = ResolutionForcer(SimpleNamespace(hook_handler=object()))
        forcer._vm = object()

        self.assertTrue(forcer.installed)

    async def test_partial_uninstall_retains_only_the_failed_hook_for_retry(self):
        class RetryableHook:
            def __init__(self, fail_first=False):
                self.attempts = 0
                self.fail_first = fail_first

            async def unhook(self):
                self.attempts += 1
                if self.fail_first and self.attempts == 1:
                    raise RuntimeError("hook still executing")

        forcer = ResolutionForcer(SimpleNamespace(hook_handler=object()))
        setmode = RetryableHook()
        video_manager = RetryableHook(fail_first=True)
        forcer._setmode = setmode
        forcer._vm = video_manager

        with self.assertRaisesRegex(RuntimeError, "hook still executing"):
            await forcer.uninstall()

        self.assertIsNone(forcer._setmode)
        self.assertIs(forcer._vm, video_manager)
        self.assertTrue(forcer.installed)

        await forcer.uninstall()

        self.assertFalse(forcer.installed)
        self.assertEqual(setmode.attempts, 1)
        self.assertEqual(video_manager.attempts, 2)

    async def test_resolution_install_preserves_activation_and_all_cleanup_failures(self):
        activation_error = RuntimeError("video-manager install failed")
        setmode_cleanup_error = RuntimeError("setmode rollback failed")
        video_cleanup_error = ValueError("video-manager rollback failed")
        setmode = SimpleNamespace(
            hook=AsyncMock(),
            unhook=AsyncMock(side_effect=setmode_cleanup_error),
        )
        video_manager = SimpleNamespace(
            hook=AsyncMock(side_effect=activation_error),
            unhook=AsyncMock(side_effect=video_cleanup_error),
        )
        handler = SimpleNamespace(_check_for_autobot=AsyncMock())
        forcer = ResolutionForcer(SimpleNamespace(hook_handler=handler))

        with (
            patch(
                "wizwalker.extensions.wizsprinter.resolution_hook.SetModeResHook",
                return_value=setmode,
            ),
            patch(
                "wizwalker.extensions.wizsprinter.resolution_hook.VideoManagerHook",
                return_value=video_manager,
            ),
        ):
            with self.assertRaisesRegex(
                RuntimeError, "video-manager install failed"
            ) as caught:
                await forcer.install()

        self.assertIs(caught.exception, activation_error)
        cleanup_error = caught.exception.cleanup_errors[0]
        self.assertIs(cleanup_error, setmode_cleanup_error)
        self.assertEqual(cleanup_error.cleanup_errors, (video_cleanup_error,))
        self.assertIs(forcer._setmode, setmode)
        self.assertIs(forcer._vm, video_manager)

    async def test_partial_install_remains_owned_for_teardown(self):
        class PartialForcer:
            def __init__(self, client):
                self.installed = True

            async def install(self):
                raise RuntimeError("partial install")

        manager = ClientResizingManager()
        with patch("src.client_resizing.ResolutionForcer", PartialForcer):
            await manager._ensure_forcer(SimpleNamespace(), 0x1234)

        self.assertIsInstance(manager._forcers[0x1234], PartialForcer)

    async def test_failed_teardown_retains_hook_for_retry(self):
        class RetryableHook:
            def __init__(self):
                self.attempts = 0

            async def uninstall(self):
                self.attempts += 1
                if self.attempts == 1:
                    raise RuntimeError("hook still executing")

        manager = ClientResizingManager()
        hook = RetryableHook()
        manager._forcers[0x1234] = hook

        with patch("src.client_resizing.disarm_window"):
            with self.assertRaisesRegex(RuntimeError, "hook still executing"):
                await manager.teardown_client(0x1234)
            self.assertIs(manager._forcers[0x1234], hook)
            self.assertIn(0x1234, manager._suspended)

            await manager.teardown_client(0x1234)

        self.assertNotIn(0x1234, manager._forcers)
        self.assertEqual(hook.attempts, 2)

    async def test_resize_teardown_retains_failures_from_both_owned_hooks(self):
        forcer_error = RuntimeError("forcer teardown failed")
        border_error = ValueError("border teardown failed")
        manager = ClientResizingManager()
        manager._forcers[0x2345] = SimpleNamespace(
            uninstall=AsyncMock(side_effect=forcer_error)
        )
        manager._borders[0x2345] = SimpleNamespace(
            uninstall=AsyncMock(side_effect=border_error)
        )

        with self.assertRaisesRegex(
            RuntimeError, "forcer teardown failed"
        ) as caught:
            await manager.teardown_client(0x2345)

        self.assertIs(caught.exception, forcer_error)
        self.assertEqual(caught.exception.cleanup_errors, (border_error,))
        self.assertIn(0x2345, manager._forcers)
        self.assertIn(0x2345, manager._borders)

    async def test_resize_owner_persists_across_two_failures_until_third_success(self):
        class RetryableHook:
            def __init__(self):
                self.attempts = 0

            async def uninstall(self):
                self.attempts += 1
                if self.attempts < 3:
                    raise RuntimeError(f"teardown attempt {self.attempts} failed")

        manager = ClientResizingManager()
        hook = RetryableHook()
        manager._forcers[0x5678] = hook

        with patch("src.client_resizing.disarm_window"):
            for attempt in (1, 2):
                with self.assertRaisesRegex(
                    RuntimeError, f"teardown attempt {attempt} failed"
                ):
                    await manager.teardown_client(0x5678)
                self.assertEqual(manager.owned_client_identities(), (0x5678,))
                self.assertIs(manager._forcers[0x5678], hook)

            await manager.teardown_client(0x5678)

        self.assertEqual(manager.owned_client_identities(), ())
        self.assertEqual(hook.attempts, 3)

    async def test_disabling_retries_retained_teardown_before_latching_disabled(self):
        class RetryableHook:
            def __init__(self):
                self.attempts = 0

            async def uninstall(self):
                self.attempts += 1
                if self.attempts == 1:
                    raise RuntimeError("hook still executing")

        manager = ClientResizingManager()
        manager._enabled = True
        hook = RetryableHook()
        manager._forcers[0x1234] = hook

        with patch("src.client_resizing.disarm_window"):
            with self.assertRaisesRegex(RuntimeError, "hook still executing"):
                await manager.tick([], enabled=False)

            self.assertTrue(manager._enabled)
            self.assertIs(manager._forcers[0x1234], hook)

            await manager.tick([], enabled=False)

        self.assertFalse(manager._enabled)
        self.assertNotIn(0x1234, manager._forcers)
        self.assertEqual(hook.attempts, 2)

    async def test_teardown_waits_for_in_flight_resize_service(self):
        class Hook:
            def __init__(self):
                self.uninstalled = False

            async def uninstall(self):
                self.uninstalled = True

        manager = ClientResizingManager()
        hook = Hook()
        manager._forcers[0x1234] = hook
        manager._ensure_forcer = AsyncMock()
        manager._ensure_border = AsyncMock()
        manager._update_border = AsyncMock()
        entered = asyncio.Event()
        release = asyncio.Event()

        async def hold_resize(_client, _hwnd):
            entered.set()
            await release.wait()

        manager._handle_resize = hold_resize
        with (
            patch("src.client_resizing.arm_window"),
            patch("src.client_resizing.correct_aspect", new=AsyncMock()),
            patch("src.client_resizing.disarm_window"),
        ):
            service_task = asyncio.create_task(
                manager._service_client(SimpleNamespace(), 0x1234)
            )
            await entered.wait()
            teardown_task = asyncio.create_task(manager.teardown_client(0x1234))
            await asyncio.sleep(0)

            self.assertFalse(hook.uninstalled)
            self.assertIn(0x1234, manager._suspended)

            release.set()
            await service_task
            await teardown_task

        self.assertTrue(hook.uninstalled)


if __name__ == "__main__":
    unittest.main()
