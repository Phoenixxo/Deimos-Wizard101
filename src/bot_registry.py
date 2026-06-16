"""Fetching and filtering for the approved bot registry repo (Deimos-Wizard101/bots).

All functions here are synchronous (requests-based) and meant to be called via
asyncio.to_thread from the backend so the GUI never blocks on network I/O.
"""

import re
from urllib.parse import quote

import requests

registry_repo: str = 'Deimos-Wizard101/bots'
registry_branch: str = 'main'
registry_raw_base: str = f'https://raw.githubusercontent.com/{registry_repo}/{registry_branch}'

_request_timeout: float = 10.0
_clients_constraint_pattern = re.compile(r'^(==|!=|>=|<=|>|<)\s*(\d+)$')
_clients_constraint_ops = {
    '==': lambda count, value: count == value,
    '!=': lambda count, value: count != value,
    '>=': lambda count, value: count >= value,
    '<=': lambda count, value: count <= value,
    '>': lambda count, value: count > value,
    '<': lambda count, value: count < value,
}


def clients_compatible(constraint, client_count: int) -> bool:
    """Evaluate an optional `@clients` constraint (e.g. '== 4', '>= 1') against the
    current client count. Missing or malformed constraints count as compatible."""
    if not constraint or not isinstance(constraint, str):
        return True
    match = _clients_constraint_pattern.match(constraint.strip())
    if not match:
        return True
    op, value = match.group(1), int(match.group(2))
    return _clients_constraint_ops[op](client_count, value)


def _get_registry_json(url: str):
    """GET a registry JSON file. A zone with no bots has no registry.json, so 404 returns None."""
    resp = requests.get(url, timeout=_request_timeout)
    if resp.status_code == 404:
        return None
    resp.raise_for_status()
    return resp.json()


def _zone_registry_url(zone: str) -> str:
    return f'{registry_raw_base}/bots/{quote(zone, safe="/")}/registry.json'


def _is_general(bot: dict) -> bool:
    return str(bot.get('world') or bot.get('zone') or '').split('/')[0] == 'General'


def search_compatible_bots(zone: str, client_count: int) -> list[dict]:
    """Return bots for the given zone plus all General bots, filtered by client count.

    Zone bots sort before General ones and entries are deduped by path. General
    entries come from each General zone's registry.json (rich, with descriptions),
    falling back to the slim index.json entries if a per-zone fetch fails.
    """
    candidates = []
    zone_data = _get_registry_json(_zone_registry_url(zone)) if zone else None
    if zone_data:
        candidates.extend(zone_data.get('bots', []))

    index = _get_registry_json(f'{registry_raw_base}/index.json') or {}
    general_zones = sorted(z for z in index.get('zones', {}) if str(z).split('/')[0] == 'General')
    for general_zone in general_zones:
        if general_zone == zone:
            continue
        try:
            general_data = _get_registry_json(_zone_registry_url(general_zone))
        except requests.RequestException:
            general_data = None
        if general_data:
            candidates.extend(general_data.get('bots', []))
        else:
            candidates.extend(b for b in index.get('bots', []) if b.get('zone') == general_zone)

    seen_paths = set()
    results = []
    for bot in candidates:
        path = bot.get('path')
        if not path or path in seen_paths:
            continue
        seen_paths.add(path)
        if not clients_compatible(bot.get('clients'), client_count):
            continue
        bot = dict(bot)
        bot['is_general'] = _is_general(bot)
        results.append(bot)
    results.sort(key=lambda b: b['is_general'])
    return results


def fetch_bot_text(path: str) -> str:
    """Download a bot's .txt content given its repo-relative path from the registry."""
    resp = requests.get(f'{registry_raw_base}/{quote(path, safe="/")}', timeout=_request_timeout)
    resp.raise_for_status()
    return resp.text
