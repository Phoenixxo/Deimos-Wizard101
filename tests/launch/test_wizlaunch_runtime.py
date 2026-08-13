import importlib
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


WIZLAUNCH_SOURCE = Path(__file__).resolve().parents[2] / "libs" / "wizlaunch" / "python"
sys.path.insert(0, str(WIZLAUNCH_SOURCE))
wizlaunch = importlib.import_module("wizlaunch")


def client_response(client_id: str, pid: int) -> dict:
    return {
        "launched_process_id": pid,
        "client": {
            "client_id": client_id,
            "process": {
                "pid": pid,
                "name": "WizardGraphicalClient.exe",
            },
            "is_foreground": False,
            "screen_order": 0,
        },
    }


class FakeAgentManager:
    def __init__(self, launch_results=()):
        self.launch_results = list(launch_results)
        self.launch_calls = []
        self.terminate_calls = []
        self.login_calls = []
        self.clients = []
        self.accounts = []
        self.gids = {}

    def launch_game(self, game_path, login_server, timeout_secs):
        self.launch_calls.append((game_path, login_server, timeout_secs))
        if not self.launch_results:
            raise AssertionError("no launch result was configured")
        result = self.launch_results.pop(0)
        if isinstance(result, BaseException):
            raise result
        self.clients.append(result["client"])
        return result

    def terminate_game(self, client_id, timeout_secs):
        self.terminate_calls.append((client_id, timeout_secs))
        self.clients = [
            client for client in self.clients if client["client_id"] != client_id
        ]
        return {
            "client_id": client_id,
            "process_id": 101,
            "terminated": True,
        }

    def list_clients(self):
        return {"clients": list(self.clients)}

    def login_account(self, nickname, client_id, timeout_secs):
        self.login_calls.append((nickname, client_id, timeout_secs))
        return {"client_id": client_id, "authenticated": True}

    def prompt_save_account(self, nickname):
        if nickname not in self.accounts:
            self.accounts.append(nickname)

    def delete_account(self, nickname):
        self.accounts.remove(nickname)
        self.gids.pop(nickname, None)

    def list_accounts(self):
        return list(self.accounts)

    def reorder_accounts(self, ordered):
        self.accounts = list(ordered)

    def has_account(self, nickname):
        return nickname in self.accounts

    def update_player_gid(self, nickname, gid):
        self.gids[nickname] = gid

    def get_player_gid(self, nickname):
        return self.gids.get(nickname)

    def get_nickname_by_gid(self, gid):
        return next(
            (nickname for nickname, value in self.gids.items() if value == gid),
            None,
        )


class FakeNativeBackend:
    def __init__(self):
        self.launch_calls = []
        self.kill_calls = []

    def launch_instance(self, nickname, game_path, login_server, timeout_secs):
        self.launch_calls.append((nickname, game_path, login_server, timeout_secs))
        return 0x1234

    def launch_instances(self, nicknames, game_path, login_server, timeout_secs):
        return {nickname: 0x1234 + index for index, nickname in enumerate(nicknames)}

    def kill_instance(self, handle):
        self.kill_calls.append(handle)
        return True

    def get_wizard_handles(self):
        return [0x1234]

    def list_accounts(self):
        return ["main"]

    def has_account(self, nickname):
        return nickname == "main"


def coded_error(code: str):
    error = RuntimeError(code)
    error.code = code
    return error


class WizlaunchRuntimeTests(unittest.TestCase):
    def tearDown(self):
        wizlaunch.clear_runtime()

    def test_public_version_remains_available(self):
        self.assertEqual(wizlaunch.__version__, "0.3.1")

    def test_runtime_must_be_selected_before_wine_launch(self):
        with patch.object(wizlaunch.sys, "platform", "darwin"):
            with self.assertRaises(wizlaunch.RuntimeNotConfiguredError) as raised:
                wizlaunch.launch_instance("main", r"C:\Wizard101")

        self.assertEqual(raised.exception.code, "runtime_not_configured")
        self.assertEqual(raised.exception.operation, "game.launch")
        self.assertIn("Choose a Wizard101 bottle", str(raised.exception))

    def test_single_launch_requires_agent_process_and_window_confirmation(self):
        agent = FakeAgentManager([client_response("client-1", 101)])
        routed = []
        wizlaunch.configure_runtime(
            agent,
            login_router=lambda nickname, client: routed.append(
                (nickname, client["client_id"])
            ),
        )

        client_id = wizlaunch.launch_instance(
            "main",
            r"C:\Wizard101",
            timeout_secs=12,
        )

        self.assertEqual(client_id, "client-1")
        self.assertEqual(
            agent.launch_calls,
            [(r"C:\Wizard101", wizlaunch.DEFAULT_LOGIN_SERVER, 12)],
        )
        self.assertEqual(routed, [("main", "client-1")])
        self.assertEqual(wizlaunch.get_wizard_handles(), ["client-1"])

    def test_multiple_launches_keep_distinct_client_ids_and_partial_timeouts(self):
        agent = FakeAgentManager(
            [
                client_response("client-1", 101),
                coded_error("game_launch_timeout"),
                client_response("client-3", 103),
            ]
        )
        wizlaunch.configure_runtime(agent)

        result = wizlaunch.launch_instances(
            ["first", "second", "third"],
            r"C:\Wizard101",
        )

        self.assertEqual(result, {"first": "client-1", "third": "client-3"})
        self.assertEqual(len(agent.launch_calls), 3)
        self.assertEqual(
            agent.login_calls,
            [("first", "client-1", 30), ("third", "client-3", 30)],
        )

    def test_non_timeout_launch_failures_remain_actionable(self):
        agent = FakeAgentManager([coded_error("game_launch_failed")])
        wizlaunch.configure_runtime(agent)

        with self.assertRaisesRegex(RuntimeError, "game_launch_failed"):
            wizlaunch.launch_instances(["main"], r"C:\Wizard101")

    def test_termination_routes_opaque_client_id_to_agent(self):
        agent = FakeAgentManager([client_response("client-1", 101)])
        wizlaunch.configure_runtime(agent)
        client_id = wizlaunch.launch_instance("main", r"C:\Wizard101")

        self.assertTrue(wizlaunch.kill_instance(client_id))
        self.assertEqual(agent.terminate_calls, [("client-1", 30)])
        self.assertEqual(wizlaunch.get_wizard_handles(), [])

    def test_invalid_agent_and_client_identity_have_structured_errors(self):
        with self.assertRaises(wizlaunch.RuntimeNotConfiguredError) as raised:
            wizlaunch.configure_runtime(object())
        self.assertEqual(raised.exception.code, "runtime_invalid")

        wizlaunch.configure_runtime(FakeAgentManager())
        with self.assertRaises(wizlaunch.WizlaunchError) as raised:
            wizlaunch.kill_instance(123)
        self.assertEqual(raised.exception.code, "client_identity_invalid")

    def test_account_management_routes_to_native_manager_without_secret_api(self):
        agent = FakeAgentManager()
        wizlaunch.configure_runtime(agent)
        wizlaunch.prompt_save_account("main")
        wizlaunch.update_player_gid("main", 42)
        self.assertEqual(wizlaunch.list_accounts(), ["main"])
        self.assertTrue(wizlaunch.has_account("main"))
        self.assertEqual(wizlaunch.get_player_gid("main"), 42)
        self.assertEqual(wizlaunch.get_nickname_by_gid(42), "main")
        self.assertFalse(hasattr(wizlaunch, "read_credential"))
        self.assertFalse(hasattr(agent, "read_credential"))
        wizlaunch.delete_account("main")
        self.assertEqual(wizlaunch.list_accounts(), [])

    def test_account_storage_requires_a_native_backend(self):
        with patch.object(wizlaunch.sys, "platform", "darwin"):
            self.assertEqual(wizlaunch.list_accounts(), [])
            self.assertFalse(wizlaunch.has_account("main"))
            with self.assertRaises(wizlaunch.AccountStorageUnavailableError) as raised:
                wizlaunch.prompt_save_account("main")

        self.assertEqual(raised.exception.code, "account_storage_unavailable")
        self.assertNotIn("password", vars(raised.exception))

    def test_automatic_login_receives_only_nickname_and_opaque_client_id(self):
        agent = FakeAgentManager([client_response("client-1", 101)])
        wizlaunch.configure_runtime(agent)

        result = wizlaunch.launch_instance("main", r"C:\Wizard101", timeout_secs=18)

        self.assertEqual(result, "client-1")
        self.assertEqual(agent.login_calls, [("main", "client-1", 18)])

    def test_windows_calls_remain_on_legacy_native_backend(self):
        native = FakeNativeBackend()
        with patch.object(wizlaunch, "_native", native), patch.object(
            wizlaunch.sys, "platform", "win32"
        ):
            handle = wizlaunch.launch_instance(
                "main",
                r"C:\Wizard101",
                "login.example:12000",
                20,
            )
            self.assertEqual(handle, 0x1234)
            self.assertTrue(wizlaunch.kill_instance(handle))
            self.assertEqual(wizlaunch.get_wizard_handles(), [0x1234])
            self.assertEqual(wizlaunch.list_accounts(), ["main"])
            self.assertTrue(wizlaunch.has_account("main"))

        self.assertEqual(
            native.launch_calls,
            [("main", r"C:\Wizard101", "login.example:12000", 20)],
        )
        self.assertEqual(native.kill_calls, [0x1234])


if __name__ == "__main__":
    unittest.main()
