"""Glue between Deimos and the HiveMind library (libs/hivemind).

Keeps all HiveMind wiring in one place so Deimos.py / the deimoslang VM only
need a handful of calls. A single ``HiveMindManager`` owns a per-client
``HiveMindProtocol``, routes the bot-offer prompt through the GUI, and exposes
enable/role/seek/offer controls.

Deimos injects three callbacks (so this module stays decoupled from the GUI and
the bot runner):
  * ``send_to_gui(command_type_name, data)`` -- enqueue a GUICommand for the GUI
  * ``run_bot_text(text)``                   -- run a bot's text on local clients
  * ``client_count()``                       -- current managed client count

Everything is a no-op until ``set_enabled(True, clients)`` is called.
"""

import asyncio
import logging
import time
from typing import Awaitable, Callable, Dict, Optional

from loguru import logger

from hivemind import HiveMindProtocol, ChatStegCipher, Role
from . import bot_registry


# The HiveMind library logs via the stdlib "hivemind" logger (it stays
# framework-agnostic). Deimos is a windowed app where print() is invisible, so
# forward those records into loguru -> they land in the Deimos log file.
class _LoguruBridge(logging.Handler):
    def emit(self, record):
        try:
            level = record.levelname if record.levelname in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL") else "INFO"
            logger.opt(exception=record.exc_info).log(level, record.getMessage())
        except Exception:
            pass


def _bridge_hivemind_logging():
    hl = logging.getLogger("hivemind")
    if not any(isinstance(h, _LoguruBridge) for h in hl.handlers):
        hl.addHandler(_LoguruBridge())
        hl.setLevel(logging.INFO)
        hl.propagate = False


_bridge_hivemind_logging()

# Resolver lives in teleport_math (collision-aware magic-grid point). Imported
# lazily inside attach() so a shapely/numpy import hiccup can't break module load.


class HiveMindManager:
    def __init__(self):
        self.enabled: bool = False
        self.role: Role = Role.SLAVE
        # Persisted "looking for team-up" intent, applied to protocols as they
        # attach so toggling it before enabling (or before a client hooks in)
        # isn't lost.
        self._seeking: bool = False
        # Shared steg encoder (the corpus model is a process-wide singleton).
        self._encoder = ChatStegCipher()
        self._protocols: Dict[object, HiveMindProtocol] = {}

        # Injected by Deimos via configure().
        self._send_to_gui: Optional[Callable[[str, object], None]] = None
        self._run_bot_text: Optional[Callable[[str], Awaitable[None]]] = None
        self._client_count: Optional[Callable[[], int]] = None

        self._pending_offers: Dict[int, "asyncio.Future[bool]"] = {}
        self._offer_seq = 0
        # The bot index we last offered, and whether we've already run it
        # locally (master runs the same bot once, on the first acceptance).
        self._offer_index: Optional[int] = None
        self._offer_ran: bool = False

        # VM.step() can fire very fast; throttle the (entity-scanning) liveness
        # check so it runs at instruction boundaries without hammering memory.
        self._last_check = 0.0
        self._check_min_interval = 0.75

    # ----- setup -----

    def configure(self, send_to_gui, run_bot_text, client_count):
        self._send_to_gui = send_to_gui
        self._run_bot_text = run_bot_text
        self._client_count = client_count

    def _grid_resolver(self):
        # Return *ranked* candidates so discovery can verify each teleport stuck
        # and fall through when the game bounces us off an unmodeled warp volume.
        from .teleport_math import find_walkable_magic_points
        from hivemind import MAGIC_FACTOR
        return lambda c: find_walkable_magic_points(c, MAGIC_FACTOR)

    # ----- enable / role -----

    async def set_enabled(self, enabled: bool, clients):
        """Enable = become discoverable + idle. We teleport onto the grid and
        handshake with peers, but stay idle (not seeking, not offering) until
        the user clicks 'Looking to team up' or 'Offer'."""
        self.enabled = enabled
        self._seeking = False  # idle until an explicit action
        if enabled:
            for c in list(clients):
                await self.attach(c)
        else:
            for c in list(self._protocols.keys()):
                await self.detach(c)
        self._push_status()

    async def attach(self, client):
        """Activate chat hooks + start a protocol for a client (idempotent)."""
        if not self.enabled or client in self._protocols:
            return
        try:
            await client.hook_handler.activate_chat_send_hook()
            await client.hook_handler.activate_chat_hook(wait_for_ready=False)
        except Exception as e:
            logger.error(f"[hivemind] chat hook activation failed: {e}")
            return

        proto = HiveMindProtocol(
            client,
            role=self.role,
            grid_resolver=self._grid_resolver(),
            encoder=self._encoder,
        )
        proto.on_bot_offer = self._make_offer_handler(client)
        proto.on_bot_accepted = self._on_bot_accepted
        proto.on_bot_rejected = self._on_bot_rejected
        proto.on_peer_lost = self._on_peer_change
        proto.on_peer_end = self._on_peer_change
        proto.on_peer_left = self._on_peer_change
        proto.on_peer_pause = self._on_peer_pause
        proto.on_peer_resume = self._on_peer_resume

        if self._seeking:
            proto.start_seeking()
        proto.own_name = getattr(client, "wizard_name", None)
        self._protocols[client] = proto
        try:
            await proto.start(discover=True)
            logger.info(f"[hivemind] attached to '{getattr(client, 'title', client)}' as {self.role.name} (seeking={self._seeking})")
        except Exception as e:
            logger.error(f"[hivemind] start failed: {e}")
            self._protocols.pop(client, None)
        self._push_status()

    async def detach(self, client):
        proto = self._protocols.pop(client, None)
        if proto is None:
            return
        try:
            await proto.announce_leave()   # best-effort graceful goodbye
        except Exception:
            pass
        try:
            await proto.stop()
        except Exception as e:
            logger.debug(f"[hivemind] stop error: {e}")
        try:
            await client.hook_handler.deactivate_chat_hook()
            await client.hook_handler.deactivate_chat_send_hook()
        except Exception:
            pass
        self._push_status()

    async def sync_clients(self, clients):
        """Attach to new clients / detach from gone ones (call on client churn)."""
        if not self.enabled:
            return
        current = set(clients)
        for c in current:
            if c not in self._protocols:
                await self.attach(c)
        for c in list(self._protocols.keys()):
            if c not in current:
                await self.detach(c)

    # ----- actions -----

    def _refresh_own_names(self):
        """Re-read each client's wizard_name (it may be set after attach)."""
        for client, proto in self._protocols.items():
            name = getattr(client, "wizard_name", None)
            if name:
                proto.own_name = name

    def start_seeking(self):
        self._seeking = True
        self._refresh_own_names()
        for proto in self._protocols.values():
            proto.start_seeking()
        logger.info(f"[hivemind] looking for team-up ({len(self._protocols)} protocol(s))")
        self._push_status()

    async def offer_bot(self, bot_index: int):
        """Offer a bot (zone-list index) to all confirmed peers. Offering makes
        us a master for this bot; we also start seeking so we still receive
        offers from other masters (whoever ends up the slave just won't offer)."""
        if not self._protocols:
            logger.warning(f"[hivemind] offer #{bot_index} ignored: HiveMind not enabled")
            return 0
        self._seeking = True
        self._offer_index = bot_index   # master runs this same bot on first accept
        self._offer_ran = False
        self._refresh_own_names()
        total = 0
        for proto in self._protocols.values():
            proto.seeking = True  # receive offers too, without clearing blocklist
            confirmed = len(proto.confirmed_peers())
            sent = await proto.offer_bot(bot_index)
            logger.info(f"[hivemind] offer_bot #{bot_index}: {confirmed} confirmed peer(s), sent to {len(sent)}")
            total += len(sent)
        self._push_status()
        return total

    async def check_all_peers(self):
        """Liveness check between bot instructions (cheap when no peers)."""
        if not self.enabled or not self._protocols:
            return
        now = time.monotonic()
        if now - self._last_check < self._check_min_interval:
            return
        self._last_check = now
        for proto in self._protocols.values():
            try:
                await proto.check_peers()
            except Exception as e:
                logger.debug(f"[hivemind] check_peers error: {e}")

    def resolve_offer(self, offer_id: int, accepted: bool):
        fut = self._pending_offers.get(offer_id)
        if fut is not None and not fut.done():
            fut.set_result(accepted)

    def peer_count(self) -> int:
        return sum(len(p.confirmed_peers()) for p in self._protocols.values())

    # ----- internal callbacks -----

    def _make_offer_handler(self, client):
        async def handler(sender_gid: int, bot_index: int) -> bool:
            zone = ""
            try:
                zone = await client.zone_name()
            except Exception:
                pass
            # No client-count filter: the master offered an index into the
            # unfiltered zone list, so we must enumerate the same list to match it.
            try:
                bots = await asyncio.to_thread(bot_registry.search_compatible_bots, zone, None)
            except Exception as e:
                logger.error(f"[hivemind] bot lookup failed: {e}")
                return False
            if not (0 <= bot_index < len(bots)):
                logger.warning(f"[hivemind] offered bot #{bot_index} out of range for '{zone}'")
                return False
            bot = bots[bot_index]
            name = bot.get("name") or "Unknown"
            path = bot.get("path")

            offer_id = self._offer_seq
            self._offer_seq += 1
            fut: "asyncio.Future[bool]" = asyncio.get_event_loop().create_future()
            self._pending_offers[offer_id] = fut
            from_name = self._peer_name(client, sender_gid)
            logger.info(f"[hivemind] prompting user: bot '{name}' (#{bot_index}) from {from_name}, offer_id={offer_id}")
            self._gui("ShowBotOfferDialog", {
                "offer_id": offer_id, "from_name": from_name,
                "bot_index": bot_index, "bot_name": name, "zone": zone,
            })
            try:
                accepted = await asyncio.wait_for(fut, timeout=180)
            except asyncio.TimeoutError:
                accepted = False
            finally:
                self._pending_offers.pop(offer_id, None)

            if accepted:
                await self._resolve_and_run(client, bot_index)
            return accepted
        return handler

    def _peer_name(self, client, gid: int) -> str:
        """A peer's wizard name for the UI (never a GID)."""
        proto = self._protocols.get(client)
        peer = proto.peers.get(gid) if proto else None
        return (peer.name if peer and peer.name else None) or "a nearby teammate"

    async def _resolve_and_run(self, client, bot_index: int) -> bool:
        """Resolve a bot by its zone-list index and run it on local clients.
        Shared by the slave (on accept) and the master (on a slave's accept) so
        both parties execute the same bot."""
        try:
            zone = await client.zone_name()
        except Exception:
            zone = ""
        try:
            bots = await asyncio.to_thread(bot_registry.search_compatible_bots, zone, None)
        except Exception as e:
            logger.error(f"[hivemind] bot lookup failed: {e}")
            return False
        if not (0 <= bot_index < len(bots)):
            logger.warning(f"[hivemind] bot #{bot_index} out of range for '{zone}'")
            return False
        path = bots[bot_index].get("path")
        if not (path and self._run_bot_text):
            return False
        try:
            text = await asyncio.to_thread(bot_registry.fetch_bot_text, path)
            await self._run_bot_text(text)
            logger.info(f"[hivemind] running bot #{bot_index} '{bots[bot_index].get('name')}'")
            return True
        except Exception as e:
            logger.error(f"[hivemind] failed to run bot: {e}")
            return False

    async def _on_bot_accepted(self, sender_gid: int, bot_index: int):
        logger.info(f"[hivemind] {self._peer_name_any(sender_gid)} accepted bot #{bot_index}")
        self._push_status()
        # Master runs the same bot once, on the first acceptance, so both
        # parties execute in sync (each on its own client(s)).
        if not self._offer_ran and self._offer_index is not None and bot_index == self._offer_index:
            self._offer_ran = True
            client = next(iter(self._protocols), None)
            if client is not None:
                asyncio.create_task(self._resolve_and_run(client, bot_index))

    def _peer_name_any(self, gid: int) -> str:
        for proto in self._protocols.values():
            peer = proto.peers.get(gid)
            if peer and peer.name:
                return peer.name
        return "a teammate"

    async def _on_bot_rejected(self, sender_gid: int, bot_index: int):
        logger.info(f"[hivemind] peer {sender_gid} rejected bot #{bot_index}")

    async def _on_peer_change(self, sender_gid: int):
        self._push_status()

    async def _on_peer_pause(self, sender_gid: int):
        logger.info(f"[hivemind] peer {sender_gid} paused")

    async def _on_peer_resume(self, sender_gid: int):
        logger.info(f"[hivemind] peer {sender_gid} resumed")

    # ----- gui helpers -----

    def _gui(self, command_type_name: str, data):
        if self._send_to_gui:
            try:
                self._send_to_gui(command_type_name, data)
            except Exception as e:
                logger.debug(f"[hivemind] gui send failed: {e}")

    def _push_status(self):
        if not self.enabled:
            state = "off"
        elif self._seeking:
            state = "seeking"
        else:
            state = "on"
        self._gui("UpdateWindow", ("HiveMindStatus", f"HiveMind: {state} peers:{self.peer_count()}"))


# Process-wide manager instance.
manager = HiveMindManager()
