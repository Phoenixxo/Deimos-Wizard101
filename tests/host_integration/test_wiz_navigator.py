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

from wizwalker.extensions.wizsprinter import wiz_navigator  # noqa: E402


class ZoneNavigationTests(unittest.IsolatedAsyncioTestCase):
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


if __name__ == "__main__":
    unittest.main()
