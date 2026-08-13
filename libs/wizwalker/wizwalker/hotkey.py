import asyncio
from collections import Counter
from contextlib import suppress
from enum import IntFlag
import time
from typing import Callable, Union

from .constants import Keycode
from .errors import (
    HotkeyAlreadyRegistered,
    HotkeyBackendUnavailable,
    HotkeyRegistrationError,
)


class ModifierKeys(IntFlag):
    """Modifier flags accepted by the host global-hotkey service."""

    ALT = 0x1
    CTRL = 0x2
    NOREPEAT = 0x4000
    SHIFT = 0x4


class _NativeHotkeyBackend:
    def __init__(self, manager=None):
        self._manager = manager

    def _get_manager(self):
        if self._manager is None:
            try:
                import deimos_native
            except ImportError as error:
                raise HotkeyBackendUnavailable(
                    "The native Deimos extension is required for global hotkeys. "
                    "Install or package deimos_native for this platform."
                ) from error
            try:
                self._manager = deimos_native.HostHotkeyManager()
            except AttributeError as error:
                raise HotkeyBackendUnavailable(
                    "This deimos_native build does not include host global-hotkey support. "
                    "Rebuild the native extension and restart Deimos."
                ) from error
        return self._manager

    def register(self, keycode: int, modifiers: int) -> int:
        return self._get_manager().register_hotkey(keycode, modifiers)

    def unregister(self, registration_id: int) -> None:
        self._get_manager().unregister_hotkey(registration_id)

    def poll_events(self) -> list[int]:
        return list(self._get_manager().poll_events())


class _GlobalHotkeyMessageLoop:
    def __init__(self, backend=None):
        self._backend = backend
        self._messages = Counter()
        self._message_loop_task = None
        self._connected_instances = 0
        self._message_loop_delay = 0.1
        self._poll_error = None

    @property
    def backend(self):
        if self._backend is None:
            self._backend = _NativeHotkeyBackend()
        return self._backend

    async def register(self, keycode: int, modifiers: int) -> int:
        try:
            return self.backend.register(keycode, modifiers)
        except HotkeyRegistrationError:
            raise
        except Exception as error:
            raise _translate_native_error(
                error,
                keycode,
                modifiers,
                operation="hotkey.register",
            ) from error

    async def unregister(
        self,
        registration_id: int,
        keycode: int,
        modifiers: int,
    ) -> None:
        try:
            self.backend.unregister(registration_id)
        except HotkeyRegistrationError:
            raise
        except Exception as error:
            raise _translate_native_error(
                error,
                keycode,
                modifiers,
                operation="hotkey.unregister",
            ) from error
        self._messages.pop(registration_id, None)

    async def check_for_message(self, registration_id: int) -> bool:
        if self._poll_error is not None:
            raise self._poll_error
        if self._messages[registration_id] <= 0:
            return False
        self._messages[registration_id] -= 1
        if self._messages[registration_id] == 0:
            del self._messages[registration_id]
        return True

    async def message_loop(self):
        try:
            while True:
                self._messages.update(self.backend.poll_events())
                await asyncio.sleep(self._message_loop_delay)
        except asyncio.CancelledError:
            raise
        except Exception as error:
            self._poll_error = _translate_native_error(
                error,
                0,
                0,
                operation="hotkey.poll",
            )

    def connect(self):
        if self._message_loop_task is None or self._message_loop_task.done():
            self._poll_error = None
            self._message_loop_task = asyncio.create_task(self.message_loop())
        self._connected_instances += 1

    def disconnect(self):
        self._connected_instances = max(0, self._connected_instances - 1)
        if self._connected_instances == 0 and self._message_loop_task is not None:
            self._message_loop_task.cancel()
            self._message_loop_task = None
            self._messages.clear()
            self._poll_error = None

    def set_message_loop_delay(self, new_delay: float):
        if new_delay <= 0:
            raise ValueError("The global hotkey polling delay must be greater than zero")
        self._message_loop_delay = new_delay


def _translate_native_error(
    error,
    keycode: int,
    modifiers: int,
    *,
    operation: str,
):
    code = getattr(error, "code", "hotkey_native_failure")
    details = getattr(error, "details", None)
    technical_message = getattr(error, "technical_message", None)
    message = str(error) or "Deimos could not update that global shortcut."
    if code == "hotkey_conflict":
        return HotkeyAlreadyRegistered(
            keycode,
            modifiers,
            message=message,
            details=details,
            technical_message=technical_message,
        )
    return HotkeyRegistrationError(
        message,
        code=code,
        keycode=keycode,
        modifiers=modifiers,
        details=details,
        technical_message=technical_message,
        operation=getattr(error, "operation", operation),
    )


_hotkey_message_loop = _GlobalHotkeyMessageLoop()
_LISTENER_STOP = object()


class Hotkey:
    """A key combination and coroutine callback used by :class:`Listener`."""

    def __init__(
        self,
        keycode: Keycode,
        callback: Callable,
        *,
        modifiers: Union[ModifierKeys, int] = 0,
    ):
        self.keycode = keycode
        self.modifiers = modifiers
        self.callback = callback


class Listener:
    """Compatibility listener for the original WizWalker hotkey interface."""

    def __init__(self, *hotkeys: Hotkey):
        self.ready = False
        self._hotkeys = hotkeys
        self._listener = HotkeyListener()
        self._queue = asyncio.Queue()
        self._closed = False
        self._setup_lock = asyncio.Lock()

    def listen_forever(self) -> asyncio.Task:
        return asyncio.create_task(self._listen_forever_loop())

    async def _listen_forever_loop(self):
        while not self._closed:
            await self.listen()

    async def _ensure_started(self):
        async with self._setup_lock:
            if self.ready:
                return
            self._listener.start()
            try:
                for hotkey in self._hotkeys:
                    await self._listener.add_hotkey(
                        hotkey.keycode,
                        lambda hotkey=hotkey: self._queue.put(hotkey.callback),
                        modifiers=ModifierKeys(hotkey.modifiers),
                    )
            except BaseException:
                await self._listener.stop()
                raise
            self.ready = True

    async def listen(self):
        await self._ensure_started()
        callback = await self._queue.get()
        if callback is _LISTENER_STOP:
            return
        asyncio.create_task(callback())

    async def close(self):
        self._closed = True
        if self.ready:
            await self._listener.stop()
            self.ready = False
        while not self._queue.empty():
            self._queue.get_nowait()
        self._queue.put_nowait(_LISTENER_STOP)


class HotkeyListener:
    """Cross-platform global hotkey listener with asynchronous callbacks."""

    def __init__(self, *, sleep_time: float = 0.1, duplicate_window: float = 0.1):
        self.sleep_time = sleep_time
        self.duplicate_window = duplicate_window
        self._hotkeys = {}
        self._callbacks = {}
        self._last_triggered = {}
        self._callback_tasks = set()
        self._message_loop_task = None
        self._connected = False

    @property
    def is_running(self) -> bool:
        return self._message_loop_task is not None and not self._message_loop_task.done()

    def start(self):
        if self._message_loop_task:
            raise ValueError("This listener has already been started")
        _hotkey_message_loop.connect()
        self._connected = True
        self._message_loop_task = asyncio.create_task(self._message_loop())

    async def stop(self):
        first_error = None
        try:
            await self.clear()
        except HotkeyRegistrationError as error:
            first_error = error

        if self._connected:
            _hotkey_message_loop.disconnect()
            self._connected = False

        if self._message_loop_task is not None:
            self._message_loop_task.cancel()
            try:
                await self._message_loop_task
            except asyncio.CancelledError:
                pass
            except HotkeyRegistrationError as error:
                first_error = first_error or error
            self._message_loop_task = None

        callback_tasks = list(self._callback_tasks)
        for task in callback_tasks:
            task.cancel()
        if callback_tasks:
            await asyncio.gather(*callback_tasks, return_exceptions=True)
        self._callback_tasks.clear()

        if first_error is not None:
            raise first_error

    async def add_hotkey(
        self, key: Keycode, callback: Callable, *, modifiers: ModifierKeys = 0
    ):
        keycode = int(key.value)
        modifier_value = int(modifiers)
        chord = (keycode, modifier_value)
        if chord in self._hotkeys:
            raise HotkeyAlreadyRegistered(keycode, modifier_value)

        registration_id = await _hotkey_message_loop.register(keycode, modifier_value)
        self._hotkeys[chord] = registration_id
        callback_chord = (keycode, modifier_value & ~int(ModifierKeys.NOREPEAT))
        self._callbacks[callback_chord] = callback

    async def remove_hotkey(self, key: Keycode, *, modifiers: ModifierKeys = 0):
        keycode = int(key.value)
        modifier_value = int(modifiers)
        chord = (keycode, modifier_value)
        registration_id = self._hotkeys.get(chord)
        if registration_id is None:
            raise HotkeyRegistrationError(
                f"No global shortcut is registered for {key.name} with modifiers {modifier_value}.",
                code="hotkey_not_registered",
                keycode=keycode,
                modifiers=modifier_value,
            )

        await _hotkey_message_loop.unregister(
            registration_id,
            keycode,
            modifier_value,
        )
        del self._hotkeys[chord]
        callback_chord = (keycode, modifier_value & ~int(ModifierKeys.NOREPEAT))
        self._callbacks.pop(callback_chord, None)
        self._last_triggered.pop(callback_chord, None)

    @staticmethod
    async def set_global_message_loop_delay(delay: float):
        _hotkey_message_loop.set_message_loop_delay(delay)

    async def clear(self):
        first_error = None
        for (keycode, modifiers), registration_id in list(self._hotkeys.items()):
            try:
                await _hotkey_message_loop.unregister(
                    registration_id,
                    keycode,
                    modifiers,
                )
            except HotkeyRegistrationError as error:
                first_error = first_error or error
                continue
            del self._hotkeys[(keycode, modifiers)]
            callback_chord = (keycode, modifiers & ~int(ModifierKeys.NOREPEAT))
            self._callbacks.pop(callback_chord, None)
            self._last_triggered.pop(callback_chord, None)
        if first_error is not None:
            raise first_error

    async def _message_loop(self):
        while True:
            for chord, registration_id in list(self._hotkeys.items()):
                if await _hotkey_message_loop.check_for_message(registration_id):
                    callback_chord = (
                        chord[0],
                        chord[1] & ~int(ModifierKeys.NOREPEAT),
                    )
                    if chord[1] & int(ModifierKeys.NOREPEAT):
                        triggered_at = time.monotonic()
                        last_triggered = self._last_triggered.get(callback_chord)
                        if (
                            last_triggered is not None
                            and triggered_at - last_triggered < self.duplicate_window
                        ):
                            continue
                        self._last_triggered[callback_chord] = triggered_at
                    self._handle_hotkey(callback_chord)
            await asyncio.sleep(self.sleep_time)

    def _handle_hotkey(self, chord: tuple[int, int]):
        task = asyncio.create_task(self._callbacks[chord]())
        self._callback_tasks.add(task)
        task.add_done_callback(self._callback_tasks.discard)
