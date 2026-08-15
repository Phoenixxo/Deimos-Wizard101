"""Compatibility routing for Wizard101 account and process operations."""

from __future__ import annotations

import sys
from collections.abc import Callable, Iterable
from typing import Any

try:
    from . import _native
except ImportError:
    _native = None

__version__ = getattr(_native, "__version__", "0.3.1")

DEFAULT_LOGIN_SERVER = "login.us.wizard101.com:12000"


class WizlaunchError(RuntimeError):
    """Base error for account and game process routing."""


class RuntimeNotConfiguredError(WizlaunchError):
    """Raised when Wine-side operations have no selected agent runtime."""


class AccountStorageUnavailableError(WizlaunchError):
    """Raised when secure account storage is unavailable on this host."""


_agent_manager: Any = None
_generation_context: Any = None
_login_router: Callable[[str, dict[str, Any]], None] | None = None


def _error(error_type, message: str, code: str, operation: str):
    error = error_type(message)
    error.code = code
    error.operation = operation
    error.technical_message = None
    error.details = {}
    return error


def configure_runtime(
    agent_manager: Any,
    *,
    generation_context: Any = None,
    login_router: Callable[[str, dict[str, Any]], None] | None = None,
) -> None:
    """Select the already-configured bottle agent used for game operations.

    The optional login router receives only the account nickname and confirmed
    client descriptor. Authentication material must remain in a secure native
    provider and must not pass through this module.
    """
    global _agent_manager, _generation_context, _login_router
    if agent_manager is None or not all(
        callable(getattr(agent_manager, method, None))
        for method in ("launch_game", "terminate_game", "list_clients")
    ):
        raise _error(
            RuntimeNotConfiguredError,
            "The selected Wine runtime does not support Wizard101 process management.",
            "runtime_invalid",
            "runtime.configure",
        )
    if login_router is not None and not callable(login_router):
        raise TypeError("login_router must be callable")
    if (
        generation_context is None
        or not callable(getattr(generation_context, "owns", None))
        or not generation_context.owns(agent_manager)
        or not callable(getattr(generation_context, "bind_manager", None))
    ):
        raise _error(
            RuntimeNotConfiguredError,
            "The selected Wine runtime is missing its shared generation fence.",
            "runtime_generation_unbound",
            "runtime.configure",
        )
    _agent_manager = agent_manager
    _generation_context = generation_context
    _login_router = login_router


def clear_runtime() -> None:
    """Forget the selected bottle runtime without stopping its agent."""
    global _agent_manager, _generation_context, _login_router
    _agent_manager = None
    _generation_context = None
    _login_router = None


def _windows_native():
    if sys.platform == "win32" and _native is not None:
        return _native
    return None


def capture_runtime(expected_instance_id: object | None = None):
    """Capture a manager view before work is queued to another thread/task."""
    if _agent_manager is None or _generation_context is None:
        raise _error(
            RuntimeNotConfiguredError,
            "Choose a Wizard101 bottle and start its Deimos agent before using it.",
            "runtime_not_configured",
            "runtime.capture",
        )
    return _generation_context.bind_manager(expected_instance_id)


def _account_backend(operation: str, method: str, runtime_binding: Any = None):
    if _agent_manager is not None and callable(
        getattr(_agent_manager, method, None)
    ):
        return runtime_binding or capture_runtime()
    backend = _windows_native()
    if backend is None:
        raise _error(
            AccountStorageUnavailableError,
            "Secure account storage is not available on this platform yet.",
            "account_storage_unavailable",
            operation,
        )
    return backend


def _runtime(operation: str, runtime_binding: Any = None):
    if _agent_manager is None:
        raise _error(
            RuntimeNotConfiguredError,
            "Choose a Wizard101 bottle and start its Deimos agent before launching the game.",
            "runtime_not_configured",
            operation,
        )
    return runtime_binding or capture_runtime()


def prompt_save_account(nickname: str, *, _runtime_binding: Any = None) -> None:
    _account_backend("account.save", "prompt_save_account", _runtime_binding).prompt_save_account(
        nickname
    )


def delete_account(nickname: str, *, _runtime_binding: Any = None) -> None:
    _account_backend("account.delete", "delete_account", _runtime_binding).delete_account(nickname)


def list_accounts(*, _runtime_binding: Any = None) -> list[str]:
    if _agent_manager is not None and callable(
        getattr(_agent_manager, "list_accounts", None)
    ):
        runtime = _runtime_binding or capture_runtime()
        with runtime.operation():
            return list(runtime.list_accounts())
    backend = _windows_native()
    return backend.list_accounts() if backend is not None else []


def reorder_accounts(ordered: Iterable[str], *, _runtime_binding: Any = None) -> None:
    _account_backend(
        "account.reorder", "reorder_accounts", _runtime_binding
    ).reorder_accounts(list(ordered))


def has_account(nickname: str, *, _runtime_binding: Any = None) -> bool:
    if _agent_manager is not None and callable(
        getattr(_agent_manager, "has_account", None)
    ):
        runtime = _runtime_binding or capture_runtime()
        with runtime.operation():
            return bool(runtime.has_account(nickname))
    backend = _windows_native()
    return bool(backend and backend.has_account(nickname))


def validate_account(nickname: str) -> str | None:
    backend = _windows_native()
    if backend is not None:
        return backend.validate_account(nickname)
    return None


def get_account_steam(nickname: str, *, _runtime_binding: Any = None) -> bool | None:
    backend = _windows_native()
    if backend is not None:
        return backend.get_account_steam(nickname)
    return False if has_account(nickname, _runtime_binding=_runtime_binding) else None


def set_account_steam(nickname: str, steam: bool) -> None:
    backend = _windows_native()
    if backend is not None:
        backend.set_account_steam(nickname, steam)


def get_window_config(nickname: str):
    backend = _windows_native()
    return backend.get_window_config(nickname) if backend is not None else None


def set_window_config(
    nickname: str,
    x: int,
    y: int,
    width: int,
    height: int,
    resolution_width: int,
    resolution_height: int,
    locked: bool,
    borderless: bool = False,
) -> None:
    backend = _windows_native()
    if backend is not None:
        backend.set_window_config(
            nickname,
            x,
            y,
            width,
            height,
            resolution_width,
            resolution_height,
            locked,
            borderless,
        )


def clear_window_config(nickname: str) -> None:
    backend = _windows_native()
    if backend is not None:
        backend.clear_window_config(nickname)


def update_player_gid(
    nickname: str,
    gid: int,
    *,
    _runtime_binding: Any = None,
) -> None:
    _account_backend(
        "account.update_gid", "update_player_gid", _runtime_binding
    ).update_player_gid(nickname, gid)


def get_player_gid(nickname: str, *, _runtime_binding: Any = None) -> int | None:
    if _agent_manager is not None and callable(
        getattr(_agent_manager, "get_player_gid", None)
    ):
        runtime = _runtime_binding or capture_runtime()
        with runtime.operation():
            return runtime.get_player_gid(nickname)
    backend = _windows_native()
    return backend.get_player_gid(nickname) if backend is not None else None


def get_nickname_by_gid(gid: int, *, _runtime_binding: Any = None) -> str | None:
    if _agent_manager is not None and callable(
        getattr(_agent_manager, "get_nickname_by_gid", None)
    ):
        runtime = _runtime_binding or capture_runtime()
        with runtime.operation():
            return runtime.get_nickname_by_gid(gid)
    backend = _windows_native()
    return backend.get_nickname_by_gid(gid) if backend is not None else None


def _confirmed_client(response: Any) -> dict[str, Any]:
    client = response.get("client") if isinstance(response, dict) else None
    process = client.get("process") if isinstance(client, dict) else None
    if (
        not isinstance(client, dict)
        or not isinstance(client.get("client_id"), str)
        or not client["client_id"]
        or not isinstance(process, dict)
        or not isinstance(process.get("pid"), int)
        or isinstance(process.get("pid"), bool)
    ):
        raise _error(
            WizlaunchError,
            "The Wine agent started Wizard101 but returned an invalid client confirmation.",
            "launch_confirmation_invalid",
            "game.launch",
        )
    return client


def launch_instance(
    nickname: str,
    game_path: str,
    login_server: str | None = None,
    timeout_secs: int = 30,
    *,
    _runtime_binding: Any = None,
) -> int | str:
    """Launch one confirmed client using the platform-appropriate backend."""
    backend = _windows_native()
    if backend is not None and _agent_manager is None:
        return backend.launch_instance(
            nickname, game_path, login_server, timeout_secs
        )

    runtime = _runtime("game.launch", _runtime_binding)
    with runtime.operation():
        response = runtime.launch_game(
            game_path,
            login_server or DEFAULT_LOGIN_SERVER,
            timeout_secs,
        )
        client = _confirmed_client(response)
        if _login_router is not None:
            _login_router(nickname, client)
        elif callable(getattr(runtime, "login_account", None)):
            runtime.login_account(nickname, client["client_id"], timeout_secs)
        return client["client_id"]


def launch_instances(
    nicknames: Iterable[str],
    game_path: str,
    login_server: str | None = None,
    timeout_secs: int = 30,
    *,
    _runtime_binding: Any = None,
) -> dict[str, int | str]:
    """Launch and confirm each requested client in account order."""
    names = list(nicknames)
    backend = _windows_native()
    if backend is not None and _agent_manager is None:
        return backend.launch_instances(names, game_path, login_server, timeout_secs)

    runtime_binding = _runtime("game.launch", _runtime_binding)
    with runtime_binding.operation():
        results: dict[str, int | str] = {}
        for nickname in names:
            try:
                results[nickname] = launch_instance(
                    nickname,
                    game_path,
                    login_server,
                    timeout_secs,
                    _runtime_binding=runtime_binding,
                )
            except Exception as error:
                if getattr(error, "code", None) == "game_launch_timeout":
                    continue
                raise
        return results


def kill_instance(handle: int | str, *, _runtime_binding: Any = None) -> bool:
    """Terminate a legacy Windows HWND or an agent-owned client ID."""
    backend = _windows_native()
    if isinstance(handle, int) and backend is not None and _agent_manager is None:
        return bool(backend.kill_instance(handle))
    if not isinstance(handle, str) or not handle:
        raise _error(
            WizlaunchError,
            "The selected Wizard101 client does not have a valid process identity.",
            "client_identity_invalid",
            "game.terminate",
        )
    runtime = _runtime("game.terminate", _runtime_binding)
    with runtime.operation():
        response = runtime.terminate_game(handle, 30)
        return bool(isinstance(response, dict) and response.get("terminated") is True)


def get_wizard_handles(*, _runtime_binding: Any = None) -> list[int | str]:
    """Return legacy HWNDs on Windows or opaque client IDs for the Wine route."""
    backend = _windows_native()
    if backend is not None and _agent_manager is None:
        return backend.get_wizard_handles()
    runtime = _runtime("client.list", _runtime_binding)
    with runtime.operation():
        response = runtime.list_clients()
        clients = response.get("clients") if isinstance(response, dict) else None
        if not isinstance(clients, list):
            raise _error(
                WizlaunchError,
                "The Wine agent returned an invalid Wizard101 client list.",
                "client_list_invalid",
                "client.list",
            )
        return [
            client["client_id"]
            for client in clients
            if isinstance(client, dict)
            and isinstance(client.get("client_id"), str)
            and client["client_id"]
        ]


__all__ = [
    "AccountStorageUnavailableError",
    "RuntimeNotConfiguredError",
    "WizlaunchError",
    "clear_runtime",
    "clear_window_config",
    "configure_runtime",
    "capture_runtime",
    "delete_account",
    "get_account_steam",
    "get_nickname_by_gid",
    "get_player_gid",
    "get_window_config",
    "get_wizard_handles",
    "has_account",
    "kill_instance",
    "launch_instance",
    "launch_instances",
    "list_accounts",
    "prompt_save_account",
    "reorder_accounts",
    "set_account_steam",
    "set_window_config",
    "update_player_gid",
    "validate_account",
    "__version__",
]
