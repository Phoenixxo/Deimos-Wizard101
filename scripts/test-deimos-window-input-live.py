#!/usr/bin/env python3
"""Exercise agent-owned window and input operations against live Wine clients."""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
from typing import Any

import deimos_native
from wizwalker import ClientHandler


TARGET_PROCESS = "WizardGraphicalClient.exe"
REQUIRED_CAPABILITIES = {
    "client.discovery.v1",
    "client.input.v1",
    "client.window.v1",
}
DEFAULT_CX_ROOT = (
    Path.home()
    / "Applications"
    / "Wizard101.app"
    / "Contents"
    / "SharedSupport"
    / "wizard101"
)
DEFAULT_BOTTLE = (
    Path.home()
    / "Library"
    / "Application Support"
    / "Wizard101"
    / "Bottles"
    / "wizard101"
)


def integer(value: str) -> int:
    try:
        return int(value, 0)
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            "integer values must be decimal or use a prefix such as 0x57"
        ) from error


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Validate agent-owned Wizard101 window geometry and optionally exercise "
            "focus, title, keyboard, and mouseless input."
        )
    )
    parser.add_argument("--agent", required=True, help="Matching deimos-agent.exe")
    parser.add_argument("--cx-root", type=Path, default=DEFAULT_CX_ROOT)
    parser.add_argument("--bottle", type=Path, default=DEFAULT_BOTTLE)
    parser.add_argument("--target", default=TARGET_PROCESS)
    parser.add_argument("--client-index", type=int, default=0)
    parser.add_argument(
        "--background-against-index",
        type=int,
        help=(
            "Focus this second client before sending input to --client-index, proving "
            "the selected target receives background input"
        ),
    )
    parser.add_argument(
        "--exercise-title",
        action="store_true",
        help="Temporarily change the selected window title and restore it",
    )
    parser.add_argument(
        "--exercise-focus",
        action="store_true",
        help="Focus the selected client and verify the resulting window state",
    )
    parser.add_argument(
        "--exercise-keyboard",
        action="store_true",
        help="Send the selected virtual key to the selected client",
    )
    parser.add_argument("--key", type=integer, default=0x57, help="Virtual key code")
    parser.add_argument(
        "--seconds",
        type=float,
        default=0.2,
        help="How long to send the key; the default W key moves briefly",
    )
    parser.add_argument(
        "--use-post",
        action="store_true",
        help="Use PostMessageW instead of SendMessageW for exercised input",
    )
    parser.add_argument(
        "--exercise-mouse",
        action="store_true",
        help="Activate mouseless input and move to the client-relative point",
    )
    parser.add_argument("--mouse-x", type=int, default=100)
    parser.add_argument("--mouse-y", type=int, default=100)
    parser.add_argument(
        "--click",
        action="store_true",
        help="Also left-click the mouse point; choose a known-safe point first",
    )
    parser.add_argument(
        "--keep-agent",
        action="store_true",
        help="Leave the managed agent running after the check",
    )
    return parser.parse_args()


def exception_report(error: BaseException) -> dict[str, Any]:
    return {
        "type": type(error).__name__,
        "message": str(error),
        "technical_message": getattr(error, "technical_message", None),
        "code": getattr(error, "code", None),
        "operation": getattr(error, "operation", None),
        "native_context": getattr(error, "native_context", None),
        "details": getattr(error, "details", None),
    }


def indexed_client(clients: list[Any], index: int, option: str) -> Any:
    if index < 0 or index >= len(clients):
        raise ValueError(
            f"{option} {index} is outside the discovered client range 0..{len(clients) - 1}"
        )
    return clients[index]


def validate_coordinate_conversion(
    manager: deimos_native.AgentManager,
    client_id: str,
) -> dict[str, Any]:
    origin = manager.client_to_screen(client_id, 0, 0)["point"]
    offset = manager.client_to_screen(client_id, 100, 75)["point"]
    delta = {
        "x": offset["x"] - origin["x"],
        "y": offset["y"] - origin["y"],
    }
    if delta != {"x": 100, "y": 75}:
        raise RuntimeError(
            "client-to-screen conversion did not preserve the requested coordinate delta"
        )
    return {"origin": origin, "offset": offset, "delta": delta}


async def run(options: argparse.Namespace) -> tuple[int, dict[str, Any]]:
    manager: deimos_native.AgentManager | None = None
    handler: ClientHandler | None = None
    original_title: str | None = None
    original_foreground_id: str | None = None
    selected = None
    report: dict[str, Any] = {
        "schema_version": 1,
        "target_process": options.target,
        "success": False,
    }
    exit_code = 0

    try:
        manager = deimos_native.AgentManager(
            str(options.bottle),
            str(options.cx_root / "bin" / "wine"),
            options.agent,
            wineserver_executable=str(options.cx_root / "bin" / "wineserver"),
            wine_arguments=["--bottle", "wizard101"],
            wrapper_manages_wine_loader=True,
            component="window-input-live-uat",
        )
        report["agent"] = manager.start()
        capabilities = set(manager.capabilities())
        report["capabilities"] = sorted(capabilities)
        missing = REQUIRED_CAPABILITIES - capabilities
        if missing:
            raise RuntimeError(
                f"the agent did not negotiate required capabilities: {sorted(missing)}"
            )

        handler = ClientHandler(agent_manager=manager)
        clients = handler.get_new_clients()
        if not clients:
            raise RuntimeError(f"{options.target} was not found in the selected bottle")
        clients.sort(key=lambda client: client.screen_order)
        report["clients"] = [
            {
                "index": index,
                "client_id": client.client_id,
                "pid": client.process_id,
                "screen_order": client.screen_order,
                "exposes_window_handle": hasattr(client, "window_handle"),
            }
            for index, client in enumerate(clients)
        ]
        if any(client["exposes_window_handle"] for client in report["clients"]):
            raise RuntimeError("a discovered client exposed a native window handle")

        selected = indexed_client(clients, options.client_index, "--client-index")
        states = {
            client.client_id: manager.client_window_state(client.client_id)
            for client in clients
        }
        original_foreground_id = next(
            (
                client_id
                for client_id, state in states.items()
                if state.get("is_foreground") is True
            ),
            None,
        )
        report["selected_client"] = {
            "client_id": selected.client_id,
            "state": states[selected.client_id],
            "coordinate_conversion": validate_coordinate_conversion(
                manager, selected.client_id
            ),
        }

        if options.exercise_title:
            original_title = selected.title
            temporary_title = f"{original_title} [Deimos UAT]"
            selected.title = temporary_title
            observed_title = selected.title
            if observed_title != temporary_title:
                raise RuntimeError("the temporary window title was not observed")
            report["title"] = {
                "original": original_title,
                "temporary": observed_title,
                "restored": False,
            }

        if options.exercise_focus:
            selected.is_foreground = True
            if not selected.is_foreground:
                raise RuntimeError("the selected client did not become the foreground window")
            report["focus"] = {"client_id": selected.client_id, "verified": True}

        background = None
        if options.background_against_index is not None:
            background = indexed_client(
                clients,
                options.background_against_index,
                "--background-against-index",
            )
            if background.client_id == selected.client_id:
                raise ValueError(
                    "--background-against-index must select a different client"
                )
            background.is_foreground = True
            if not background.is_foreground or selected.is_foreground:
                raise RuntimeError(
                    "the second client could not establish a background-input test"
                )
            report["background_targeting"] = {
                "input_target": selected.client_id,
                "foreground_client": background.client_id,
                "verified_before_input": True,
            }

        if options.exercise_keyboard:
            keyboard = await asyncio.get_running_loop().run_in_executor(
                None,
                lambda: manager.send_key(
                    selected.client_id,
                    options.key,
                    options.seconds,
                    use_post=options.use_post,
                ),
            )
            report["keyboard"] = {
                "request": {
                    "client_id": selected.client_id,
                    "virtual_key": options.key,
                    "seconds": options.seconds,
                    "delivery": "post" if options.use_post else "send",
                },
                "response": keyboard,
                "visual_confirmation_required": True,
            }

        if options.exercise_mouse:
            async with selected.mouse_handler:
                await selected.mouse_handler.set_mouse_position(
                    options.mouse_x,
                    options.mouse_y,
                    use_post=options.use_post,
                )
                if options.click:
                    await selected.mouse_handler.click(
                        options.mouse_x,
                        options.mouse_y,
                        use_post=options.use_post,
                    )
            report["mouse"] = {
                "client_id": selected.client_id,
                "point": {"x": options.mouse_x, "y": options.mouse_y},
                "clicked": options.click,
                "delivery": "post" if options.use_post else "send",
                "visual_confirmation_required": True,
            }

        report["success"] = True
    except Exception as error:
        report["error"] = exception_report(error)
        exit_code = 1
    finally:
        cleanup_errors: list[dict[str, Any]] = []
        if selected is not None and original_title is not None:
            try:
                selected.title = original_title
                if "title" in report:
                    report["title"]["restored"] = selected.title == original_title
            except Exception as error:
                cleanup_errors.append(
                    {"operation": "client.window.restore_title", **exception_report(error)}
                )
        if manager is not None and original_foreground_id is not None:
            try:
                manager.focus_client_window(original_foreground_id)
            except Exception as error:
                cleanup_errors.append(
                    {"operation": "client.window.restore_focus", **exception_report(error)}
                )
        if handler is not None:
            try:
                await handler.close()
            except Exception as error:
                cleanup_errors.append(
                    {"operation": "client.close", **exception_report(error)}
                )
        if manager is not None and not options.keep_agent:
            try:
                manager.stop("window and input live UAT completed")
            except Exception as error:
                cleanup_errors.append(
                    {"operation": "agent.stop", **exception_report(error)}
                )
        if cleanup_errors:
            report["success"] = False
            report["cleanup_errors"] = cleanup_errors
            exit_code = 1

    return exit_code, report


def main() -> int:
    options = arguments()
    exit_code, report = asyncio.run(run(options))
    print(json.dumps(report, indent=2))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
