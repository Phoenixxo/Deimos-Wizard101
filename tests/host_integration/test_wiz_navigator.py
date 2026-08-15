from __future__ import annotations

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
for import_root in (
    REPOSITORY_ROOT / "libs" / "wizwalker",
    REPOSITORY_ROOT / "libs" / "wizsprinter",
):
    if str(import_root) not in sys.path:
        sys.path.insert(0, str(import_root))

from wizwalker import HookNotReady, MemoryReadError  # noqa: E402
from wizwalker.client import Client  # noqa: E402
from wizwalker.extensions.wizsprinter import wiz_navigator  # noqa: E402


class ZoneNavigationTests(unittest.IsolatedAsyncioTestCase):
    async def test_unbound_client_method_preserves_duck_typed_compatibility(self):
        client = SimpleNamespace(
            zone_name=AsyncMock(
                side_effect=("WizardCity/Old", "WizardCity/New", "WizardCity/New")
            ),
            is_loading=AsyncMock(return_value=False),
        )

        result = await Client.wait_for_zone_change(
            client,
            sleep_time=0,
            timeout=1,
        )

        self.assertEqual(result, "WizardCity/New")
        self.assertFalse(hasattr(client, "_require_active"))
        self.assertFalse(hasattr(client, "_require_running"))

    async def test_zone_change_wait_retries_transient_memory_gaps(self):
        client = SimpleNamespace(
            zone_name=AsyncMock(
                side_effect=(
                    "MooShu/MS_Hub",
                    MemoryReadError("tree unavailable"),
                    None,
                    "MooShu/Interiors/MS_Teleport_Chamber",
                    "MooShu/Interiors/MS_Teleport_Chamber",
                    "MooShu/Interiors/MS_Teleport_Chamber",
                )
            ),
            is_loading=AsyncMock(side_effect=(HookNotReady("Client"), False)),
        )

        result = await Client.wait_for_zone_change(
            client,
            sleep_time=0,
            timeout=1,
        )

        self.assertEqual(result, "MooShu/Interiors/MS_Teleport_Chamber")

    async def test_no_clients_returns_a_human_readable_unavailable_result(self):
        warning = Mock()
        logger = SimpleNamespace(warning=warning)

        with patch.object(wiz_navigator, "logger", logger):
            result = await wiz_navigator.toZone([], "WizardCity/WC_Ravenwood")

        self.assertEqual(result, 1)
        self.assertIn("no Wizard101 client", warning.call_args.args[0])

    async def test_loading_zone_returns_without_parsing_or_navigation(self):
        client = SimpleNamespace(zone_name=AsyncMock(return_value=None))
        logger = SimpleNamespace(warning=lambda message: None)

        with patch.object(wiz_navigator, "logger", logger), patch.object(
            wiz_navigator,
            "parseFile",
            AsyncMock(),
        ) as parse_file:
            result = await wiz_navigator.toZone(
                [client],
                "WizardCity/WC_Ravenwood",
            )

        self.assertEqual(result, 1)
        parse_file.assert_not_awaited()

    async def test_navigation_failure_is_not_reported_as_success(self):
        client = SimpleNamespace(zone_name=AsyncMock(return_value="MooShu/MS_Hub"))
        warning = Mock()
        info = Mock()
        logger = SimpleNamespace(warning=warning, info=info)

        with patch.object(wiz_navigator, "logger", logger), patch.object(
            wiz_navigator,
            "parseFile",
            AsyncMock(return_value=[]),
        ), patch.object(
            wiz_navigator,
            "createStack",
            AsyncMock(return_value=[[['MooShu/MS_Hub', 'MooShu/MS_Hub']]]),
        ), patch.object(
            wiz_navigator,
            "goToDestination",
            AsyncMock(side_effect=MemoryReadError("tree unavailable")),
        ):
            result = await wiz_navigator.toZone(
                [client],
                "Krokotopia/KT_Hub",
            )

        self.assertEqual(result, 1)
        self.assertIn("without reaching", warning.call_args.args[0])
        info.assert_not_called()

    async def test_navigation_requires_the_reported_destination_zone(self):
        client = SimpleNamespace(
            zone_name=AsyncMock(return_value="MooShu/MS_Hub"),
            is_loading=AsyncMock(return_value=False),
        )
        warning = Mock()
        info = Mock()
        logger = SimpleNamespace(warning=warning, info=info)

        with patch.object(wiz_navigator, "logger", logger), patch.object(
            wiz_navigator,
            "parseFile",
            AsyncMock(return_value=[]),
        ), patch.object(
            wiz_navigator,
            "createStack",
            AsyncMock(return_value=[[['MooShu/MS_Hub', 'MooShu/MS_Hub']]]),
        ), patch.object(
            wiz_navigator,
            "goToDestination",
            AsyncMock(),
        ):
            result = await wiz_navigator.toZone(
                [client],
                "Krokotopia/KT_Hub",
            )

        self.assertEqual(result, 1)
        self.assertIn("but it entered", warning.call_args.args[0])
        info.assert_not_called()


if __name__ == "__main__":
    unittest.main()
