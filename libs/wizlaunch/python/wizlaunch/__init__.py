"""Compatibility routing for Wizard101 account and process operations."""

from __future__ import annotations

import sys
from collections.abc import Callable, Iterable
from typing import Any

try:
    from . import _native
except ImportError:
    _native = None

__version__ = getattr(_native, "__version__", "0.2.0")

DEFAULT_LOGIN_SERVER = "login.us.wizard101.com:12000"


class WizlaunchError(RuntimeError):
    """Base error for account and game process routing."""


class RuntimeNotConfiguredError(WizlaunchError):
    """Raised when Wine-side operations have no selected agent runtime."""


class AccountStorageUnavailableError(WizlaunchError):
    """Raised when secure account storage is unavailable on this host."""


_agent_manager: Any = None
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
    login_router: Callable[[str, dict[str, Any]], None] | None = None,
) -> None:
    """Select the already-configured bottle agent used for game operations.

    The optional login router receives only the account nickname and confirmed
    client descriptor. Authentication material must remain in a secure native
    provider and must not pass through this module.
    """
    global _agent_manager, _login_router
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
    _agent_manager = agent_manager
    _login_router = login_router


def clear_runtime() -> None:
    """Forget the selected bottle runtime without stopping its agent."""
    global _agent_manager, _login_router
    _agent_manager = None
    _login_router = None


def _windows_native():
    if sys.platform == "win32" and _native is not None:
        return _native
    return None


def _account_backend(operation: str, method: str):
    if _agent_manager is not None and callable(
        getattr(_agent_manager, method, None)
    ):
        return _agent_manager
    backend = _windows_native()
    if backend is None:
        raise _error(
            AccountStorageUnavailableError,
            "Secure account storage is not available on this platform yet.",
            "account_storage_unavailable",
            operation,
        )
    return backend


def _runtime(operation: str):
    if _agent_manager is None:
        raise _error(
            RuntimeNotConfiguredError,
            "Choose a Wizard101 bottle and start its Deimos agent before launching the game.",
            "runtime_not_configured",
            operation,
        )
    return _agent_manager


def prompt_save_account(nickname: str) -> None:
    _account_backend("account.save", "prompt_save_account").prompt_save_account(
        nickname
    )


def delete_account(nickname: str) -> None:
    _account_backend("account.delete", "delete_account").delete_account(nickname)


def list_accounts() -> list[str]:
    if _agent_manager is not None and callable(
        getattr(_agent_manager, "list_accounts", None)
    ):
        return list(_agent_manager.list_accounts())
    backend = _windows_native()
    return backend.list_accounts() if backend is not None else []


def reorder_accounts(ordered: Iterable[str]) -> None:
    _account_backend("account.reorder", "reorder_accounts").reorder_accounts(
        list(ordered)
    )


def has_account(nickname: str) -> bool:
    if _agent_manager is not None and callable(
        getattr(_agent_manager, "has_account", None)
    ):
        return bool(_agent_manager.has_account(nickname))
    backend = _windows_native()
    return bool(backend and backend.has_account(nickname))


def update_player_gid(nickname: str, gid: int) -> None:
    _account_backend("account.update_gid", "update_player_gid").update_player_gid(
        nickname, gid
    )


def get_player_gid(nickname: str) -> int | None:
    if _agent_manager is not None and callable(
        getattr(_agent_manager, "get_player_gid", None)
    ):
        return _agent_manager.get_player_gid(nickname)
    backend = _windows_native()
    return backend.get_player_gid(nickname) if backend is not None else None


def get_nickname_by_gid(gid: int) -> str | None:
    if _agent_manager is not None and callable(
        getattr(_agent_manager, "get_nickname_by_gid", None)
    ):
        return _agent_manager.get_nickname_by_gid(gid)
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
) -> int | str:
    """Launch one confirmed client using the platform-appropriate backend."""
    backend = _windows_native()
    if backend is not None and _agent_manager is None:
        return backend.launch_instance(
            nickname, game_path, login_server, timeout_secs
        )

    response = _runtime("game.launch").launch_game(
        game_path,
        login_server or DEFAULT_LOGIN_SERVER,
        timeout_secs,
    )
    client = _confirmed_client(response)
    if _login_router is not None:
        _login_router(nickname, client)
    elif callable(getattr(_agent_manager, "login_account", None)):
        _agent_manager.login_account(nickname, client["client_id"], timeout_secs)
    return client["client_id"]


def launch_instances(
    nicknames: Iterable[str],
    game_path: str,
    login_server: str | None = None,
    timeout_secs: int = 30,
) -> dict[str, int | str]:
    """Launch and confirm each requested client in account order."""
    names = list(nicknames)
    backend = _windows_native()
    if backend is not None and _agent_manager is None:
        return backend.launch_instances(names, game_path, login_server, timeout_secs)

    results: dict[str, int | str] = {}
    for nickname in names:
        try:
            results[nickname] = launch_instance(
                nickname,
                game_path,
                login_server,
                timeout_secs,
            )
        except Exception as error:
            if getattr(error, "code", None) == "game_launch_timeout":
                continue
            raise
    return results


def kill_instance(handle: int | str) -> bool:
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
    response = _runtime("game.terminate").terminate_game(handle, 30)
    return bool(isinstance(response, dict) and response.get("terminated") is True)


def get_wizard_handles() -> list[int | str]:
    """Return legacy HWNDs on Windows or opaque client IDs for the Wine route."""
    backend = _windows_native()
    if backend is not None and _agent_manager is None:
        return backend.get_wizard_handles()
    response = _runtime("client.list").list_clients()
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
    "configure_runtime",
    "delete_account",
    "get_nickname_by_gid",
    "get_player_gid",
    "get_wizard_handles",
    "has_account",
    "kill_instance",
    "launch_instance",
    "launch_instances",
    "list_accounts",
    "prompt_save_account",
    "reorder_accounts",
    "update_player_gid",
    "__version__",
]
