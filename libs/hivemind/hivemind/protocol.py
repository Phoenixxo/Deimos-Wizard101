import asyncio
import logging
import struct
import time
from dataclasses import dataclass
from typing import Awaitable, Callable, Dict, List, Optional, Tuple

from .message_type import MessageType
from .encoder import ChatEncoder
from .dispatcher import MessageDispatcher
from .discovery import HiveMindDiscovery, GridResolver, Role, xy_matches
from .names import chunk_name, pack_chunk, unpack_chunk

# How many times to re-send our name to a confirmed peer (redundancy, since the
# poll-based receive loop can miss a message if two arrive within one tick).
_NAME_RESENDS = 4

_log = logging.getLogger("hivemind")


# Slave-side decision callback for an incoming bot offer:
#   async fn(sender_gid: int, bot_index: int) -> bool   (True = accept)
BotOfferHandler = Callable[[int, int], Awaitable[bool]]
# Master-side notification of a slave's reply: async fn(sender_gid, bot_index)
BotReplyHandler = Callable[[int, int], Awaitable[None]]
# A confirmed peer stopped responding: async fn(sender_gid)
PeerLostHandler = Callable[[int], Awaitable[None]]
# A peer sent a session-lifecycle message: async fn(sender_gid)
LifecycleHandler = Callable[[int], Awaitable[None]]


@dataclass
class PeerInfo:
    """A known peer and the state of our handshake with it."""
    gid: int
    role: Optional[Role] = None
    qx: Optional[int] = None
    qy: Optional[int] = None
    # True once we have received a valid HELLO/HELLO_ACK from this GID.
    confirmed: bool = False
    # True once the GID that whispered us matches the on-screen entity we
    # see at the claimed grid cell (GID <-> entity binding).
    bound: bool = False
    # Monotonic timestamp of the last message received from this peer; 0
    # until the handshake completes. Informational.
    last_seen: float = 0.0
    # True after we sent a KEEPALIVE (peer was out of range) and are still
    # waiting for its ACK. If it's still out of range on the next check, the
    # peer is declared lost.
    awaiting_ack: bool = False
    # The peer's wizard name (exchanged via NAME messages) for the UI, so we
    # never show a raw GID. None until received.
    name: Optional[str] = None
    # How many times we've sent our own name to this peer (bounded redundancy).
    name_sends: int = 0


class HiveMindProtocol:
    """Bot-to-bot communication protocol over Wizard101 directed chat.

    Wraps a WizWalker client and provides send/receive/dispatch for
    protocol messages, passive peer discovery, and bot-offer coordination.

    Discovery (``start(discover=True)``) writes a role beacon yaw, teleports
    onto the magic grid, and periodically scans the entity list, opening a
    DM handshake (HELLO/HELLO_ACK) with each peer it spots.

    Bot offers (slave side) are gated by a small state machine:
      * we only entertain offers while ``seeking`` ("looking for team up");
      * once we accept one we are ``locked_to`` that peer and auto-reject
        everyone else until ``cancel_lock`` (GUI) or the client is stopped;
      * a peer we explicitly reject is blocklisted for the current zone (or
        until ``start_seeking`` re-triggers looking-for-team-up);
      * offers arriving while a prompt is open queue and are shown in turn.

    While the team assembles, ``pin_to_grid`` holds us in place/orientation
    via continual re-teleport until the required client count is reached.
    """

    def __init__(self, client, role: Role = Role.SLAVE, grid_resolver: Optional[GridResolver] = None, encoder=None):
        self.client = client
        self.role = role
        # The wire encoder. Defaults to the plain ``HM ...`` ChatEncoder; pass
        # a ChatStegCipher to render messages as corpus-distributed chat. Both
        # clients must use the same encoder (and steg key).
        self.encoder = encoder if encoder is not None else ChatEncoder()
        self.dispatcher = MessageDispatcher()
        self.discovery = HiveMindDiscovery(client, grid_resolver=grid_resolver)

        self.peers: Dict[int, PeerInfo] = {}

        # Our own wizard name (set by the embedding app), broadcast to peers so
        # the UI can show names instead of GIDs. Inbound name chunks reassemble
        # per sender here.
        self.own_name: Optional[str] = None
        self._name_parts: Dict[int, Dict[int, str]] = {}

        # --- Bot-offer state machine (slave side) ---
        # Actively want to team up; only then are offers entertained.
        self.seeking: bool = False
        # (gid, bot_index) we accepted and are committed to, or None.
        self.locked_to: Optional[Tuple[int, int]] = None
        # GIDs whose offers we auto-reject for the current zone (explicit
        # user rejections; cleared on zone change or start_seeking()).
        self.rejected_gids: set[int] = set()
        self._offer_queue: "asyncio.Queue[Tuple[int, int]]" = asyncio.Queue()

        # --- Grid hold ("pinned") state ---
        self.pinned: bool = False
        self.required_clients: Optional[int] = None
        # How the team size is counted (default: confirmed peers + self).
        self.team_size_fn: Callable[[], int] = lambda: len(self.confirmed_peers()) + 1

        # Bot-distribution callbacks (set by the embedding app, e.g. Deimos):
        #   on_bot_offer  - slave side: prompt the user, return True to accept.
        #   on_bot_accepted / on_bot_rejected - master side: a slave replied.
        #   on_peer_lost  - a confirmed peer timed out (keepalive).
        self.on_bot_offer: Optional[BotOfferHandler] = None
        self.on_bot_accepted: Optional[BotReplyHandler] = None
        self.on_bot_rejected: Optional[BotReplyHandler] = None
        self.on_peer_lost: Optional[PeerLostHandler] = None
        # Session-lifecycle notifications from a peer (set by Deimos):
        self.on_peer_pause: Optional[LifecycleHandler] = None
        self.on_peer_resume: Optional[LifecycleHandler] = None
        self.on_peer_end: Optional[LifecycleHandler] = None
        self.on_peer_left: Optional[LifecycleHandler] = None

        self._recv_task: Optional[asyncio.Task] = None
        self._discover_task: Optional[asyncio.Task] = None
        self._offer_task: Optional[asyncio.Task] = None
        self._ka_seq = 0
        self._last_counter = 0
        self._current_zone: Optional[str] = None
        # Latest beacon sighting per GID, to bind a whispering GID to the
        # entity we physically see (anti-spoof). gid -> (qx, qy)
        self._last_scan_xy: Dict[int, Tuple[int, int]] = {}

        # Register default handlers
        self.dispatcher.register(MessageType.PING, self._handle_ping)
        self.dispatcher.register(MessageType.PONG, self._handle_pong)
        self.dispatcher.register(MessageType.HELLO, self._handle_hello)
        self.dispatcher.register(MessageType.HELLO_ACK, self._handle_hello_ack)
        self.dispatcher.register(MessageType.BOT_OFFER, self._handle_bot_offer)
        self.dispatcher.register(MessageType.BOT_ACCEPT, self._handle_bot_accept)
        self.dispatcher.register(MessageType.BOT_REJECT, self._handle_bot_reject)
        self.dispatcher.register(MessageType.KEEPALIVE, self._handle_keepalive)
        self.dispatcher.register(MessageType.KEEPALIVE_ACK, self._handle_keepalive_ack)
        self.dispatcher.register(MessageType.SESSION_PAUSE, self._handle_session_pause)
        self.dispatcher.register(MessageType.SESSION_RESUME, self._handle_session_resume)
        self.dispatcher.register(MessageType.SESSION_END, self._handle_session_end)
        self.dispatcher.register(MessageType.SESSION_LEFT, self._handle_session_left)
        self.dispatcher.register(MessageType.NAME, self._handle_name)

    # ----- lifecycle -----

    async def start(self, discover: bool = False, teleport: bool = True, scan_interval: float = 2.0):
        """Start the receive + offer loops, and optionally discovery.

        Liveness is *not* a timer: call ``check_peers()`` between bot
        instructions instead (see that method).

        Args:
            discover: If True, advertise this client's role and run the
                periodic discovery/handshake/hold loop.
            teleport: When discovering, whether to teleport onto the magic
                grid (full ``activate``); if False, only write the beacon
                yaw in place (caller has positioned the bot on the grid).
            scan_interval: Seconds between entity-list scans (also governs
                how tightly the grid hold re-pins).
        """
        self._recv_task = asyncio.create_task(self._receive_loop())
        self._offer_task = asyncio.create_task(self._offer_worker())
        if discover:
            if teleport:
                await self.discovery.activate(self.role)
            else:
                await self.discovery.set_beacon(self.role)
            self._discover_task = asyncio.create_task(self._discovery_loop(scan_interval))

    async def stop(self):
        """Stop all loops. Equivalent to leaving the hive for this client."""
        for task in (self._discover_task, self._offer_task, self._recv_task):
            if task:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
        self._recv_task = self._discover_task = self._offer_task = None

    # ----- team-up controls (driven by the GUI) -----

    def start_seeking(self):
        """Begin looking for a team-up: entertain offers and clear the
        per-zone reject blocklist (re-triggers looking-for-team-up)."""
        self.seeking = True
        self.rejected_gids.clear()

    def stop_seeking(self):
        """Stop entertaining new offers."""
        self.seeking = False

    def cancel_lock(self):
        """Release the lock to a peer (user cancelled in the GUI), so we
        can look for a different team-up again."""
        self.locked_to = None

    def pin_to_grid(self, required_clients: Optional[int] = None):
        """Hold position + beacon yaw via continual re-teleport until the
        team reaches ``required_clients`` (a bot's @clients count). With no
        count given, hold until ``unpin`` is called."""
        self.pinned = True
        self.required_clients = required_clients

    def unpin(self):
        """Stop holding the grid position."""
        self.pinned = False
        self.required_clients = None

    def confirmed_peers(self) -> List[PeerInfo]:
        """Peers we have completed a handshake with."""
        return [p for p in self.peers.values() if p.confirmed]

    def _team_satisfied(self) -> bool:
        return self.required_clients is not None and self.team_size_fn() >= self.required_clients

    def _should_auto_reject(self, sender_gid: int) -> bool:
        """An offer from this GID can't be accepted right now (committed
        elsewhere, not looking, or this peer was already declined)."""
        return self.locked_to is not None or not self.seeking or sender_gid in self.rejected_gids

    # ----- sending -----

    async def send(self, msg_type: MessageType, target_gid: int, *args: int):
        """Send a protocol message to another bot."""
        chat_str = self.encoder.encode(msg_type, *args)
        await self.client.chat_owner.send_msg(chat_str, target_gid=target_gid)

    async def offer_bot(self, bot_index: int, target_gid: Optional[int] = None) -> List[int]:
        """Offer a bot (by its zone-list index) to one or all confirmed peers.

        Returns the list of GIDs the offer was sent to.
        """
        targets = [target_gid] if target_gid is not None else [p.gid for p in self.confirmed_peers()]
        sent: List[int] = []
        for gid in targets:
            try:
                await self.send(MessageType.BOT_OFFER, gid, bot_index)
                _log.info(f"[HiveMind] BOT_OFFER bot#{bot_index} -> {gid}")
                sent.append(gid)
            except Exception as e:
                _log.info(f"[HiveMind] BOT_OFFER to {gid} failed: {e}")
        return sent

    # ----- loops -----

    async def send_name(self, target_gid: int):
        """Send our wizard name to a peer, in chunks (no-op if name unknown)."""
        if not self.own_name:
            return
        chunks = chunk_name(self.own_name)
        for idx, chunk in enumerate(chunks):
            try:
                await self.send(MessageType.NAME, target_gid, idx, len(chunks), pack_chunk(chunk))
            except Exception as e:
                _log.info(f"[HiveMind] NAME chunk {idx} to {target_gid} failed: {e}")

    async def broadcast(self, msg_type: MessageType, *args: int) -> List[int]:
        """Send a message to every confirmed peer. Returns the GIDs reached."""
        sent: List[int] = []
        for peer in self.confirmed_peers():
            try:
                await self.send(msg_type, peer.gid, *args)
                sent.append(peer.gid)
            except Exception as e:
                _log.info(f"[HiveMind] {msg_type.name} to {peer.gid} failed: {e}")
        return sent

    async def announce_pause(self) -> List[int]:
        """Tell peers we are pausing execution."""
        return await self.broadcast(MessageType.SESSION_PAUSE)

    async def announce_resume(self) -> List[int]:
        """Tell peers we are resuming execution."""
        return await self.broadcast(MessageType.SESSION_RESUME)

    async def announce_end(self) -> List[int]:
        """Tell peers we are ending execution (done coordinating)."""
        return await self.broadcast(MessageType.SESSION_END)

    async def announce_leave(self) -> List[int]:
        """Tell peers we are leaving/disconnecting gracefully. Typically
        followed by ``stop()``."""
        return await self.broadcast(MessageType.SESSION_LEFT)

    def _drop_peer(self, gid: int):
        """Forget a peer that is no longer participating, releasing any lock."""
        self.peers.pop(gid, None)
        self._last_scan_xy.pop(gid, None)
        if self.locked_to is not None and self.locked_to[0] == gid:
            self.locked_to = None

    async def _discovery_loop(self, scan_interval: float):
        """Scan for peers, hold the grid while pinned, and handshake."""
        while True:
            try:
                await asyncio.sleep(scan_interval)

                # Clear the per-zone reject blocklist when the zone changes.
                try:
                    zone = await self.client.zone_name()
                except Exception:
                    zone = self._current_zone
                if zone != self._current_zone:
                    self._current_zone = zone
                    if self.rejected_gids:
                        self.rejected_gids.clear()
                        _log.info("[HiveMind] zone changed; cleared offer blocklist")

                # Hold position until the client count is met (re-teleport to
                # the grid point if we drift off it).
                if self.pinned:
                    if self._team_satisfied():
                        self.pinned = False
                        _log.info("[HiveMind] required client count reached; releasing grid hold")
                    else:
                        try:
                            await self.discovery.repin()
                        except Exception as e:
                            _log.info(f"[HiveMind] repin failed: {e}")

                own_qx, own_qy = await self.discovery.own_quantized_xy()
                beacons = await self.discovery.scan()
                self._last_scan_xy = {b.gid: (b.qx, b.qy) for b in beacons}

                for beacon in beacons:
                    peer = self.peers.get(beacon.gid)
                    if peer is None:
                        peer = PeerInfo(gid=beacon.gid, qx=beacon.qx, qy=beacon.qy)
                        self.peers[beacon.gid] = peer
                    else:
                        peer.qx, peer.qy = beacon.qx, beacon.qy

                    # Greet peers we have not yet handshaken with. We send
                    # our OWN role + grid cell so they can bind us.
                    if not peer.confirmed:
                        try:
                            await self.send(MessageType.HELLO, beacon.gid, self.role.value, own_qx, own_qy)
                            _log.info(f"[HiveMind] HELLO -> {beacon.gid} (on-grid peer)")
                        except Exception as e:
                            _log.info(f"[HiveMind] HELLO to {beacon.gid} failed: {e}")
                    # Send our name to confirmed peers a few times (redundancy
                    # against missed messages) so the UI can show names not GIDs.
                    elif self.own_name and peer.name_sends < _NAME_RESENDS:
                        peer.name_sends += 1
                        await self.send_name(beacon.gid)

            except asyncio.CancelledError:
                raise
            except Exception as e:
                _log.info(f"[HiveMind] Discovery error: {e}")
                await asyncio.sleep(1)

    async def _offer_worker(self):
        """Process queued bot offers one at a time so each user prompt is
        shown in turn and the receive loop never blocks on a dialog."""
        while True:
            try:
                sender_gid, bot_index = await self._offer_queue.get()

                # State may have changed since this was queued.
                if self._should_auto_reject(sender_gid):
                    await self.send(MessageType.BOT_REJECT, sender_gid, bot_index)
                    continue

                accepted = False
                if self.on_bot_offer is not None:
                    try:
                        accepted = await self.on_bot_offer(sender_gid, bot_index)
                    except Exception as e:
                        _log.info(f"[HiveMind] bot offer handler error: {e}")
                        accepted = False

                # Re-check after the (possibly long) prompt: we may have been
                # locked/cancelled meanwhile -> reject without blocklisting.
                if self._should_auto_reject(sender_gid):
                    await self.send(MessageType.BOT_REJECT, sender_gid, bot_index)
                    continue

                if accepted:
                    self.locked_to = (sender_gid, bot_index)
                    self.seeking = False  # committed; stop looking
                    await self.send(MessageType.BOT_ACCEPT, sender_gid, bot_index)
                    _log.info(f"[HiveMind] locked to {sender_gid} for bot#{bot_index}")
                else:
                    self.rejected_gids.add(sender_gid)  # user declined this peer
                    await self.send(MessageType.BOT_REJECT, sender_gid, bot_index)

            except asyncio.CancelledError:
                raise
            except Exception as e:
                _log.info(f"[HiveMind] offer worker error: {e}")
                await asyncio.sleep(0.5)

    async def check_peers(self):
        """Confirm confirmed peers are still alive. Call this between bot
        instructions (no timer/interval).

        A peer we can still see in the entity list is self-evidently alive --
        no chat needed. Only for peers that have gone **out of range**
        (entity unreadable) do we fall back to a KEEPALIVE whisper:

          * in range            -> alive; clear any pending ack
          * out of range, fresh -> send one KEEPALIVE, await its ACK
          * out of range, still
            awaiting last ack    -> declare lost (on_peer_lost), drop peer

        A KEEPALIVE_ACK (or any message) from the peer clears the pending
        state via the receive loop.
        """
        if not any(p.confirmed for p in self.peers.values()):
            return  # nothing to keep alive -> skip the entity-list scan
        visible = await self.discovery.visible_player_gids()
        for gid, peer in list(self.peers.items()):
            if not peer.confirmed:
                continue
            if gid in visible:
                peer.awaiting_ack = False
                peer.last_seen = time.monotonic()
                continue
            # Out of range.
            if peer.awaiting_ack:
                _log.info(f"[HiveMind] peer {gid} out of range and unACKed; declaring lost")
                del self.peers[gid]
                self._last_scan_xy.pop(gid, None)
                if self.on_peer_lost is not None:
                    try:
                        await self.on_peer_lost(gid)
                    except Exception as e:
                        _log.info(f"[HiveMind] peer-lost handler error: {e}")
            else:
                self._ka_seq += 1
                peer.awaiting_ack = True
                try:
                    await self.send(MessageType.KEEPALIVE, gid, self._ka_seq)
                    _log.info(f"[HiveMind] peer {gid} out of range; sent KEEPALIVE")
                except Exception as e:
                    _log.info(f"[HiveMind] KEEPALIVE to {gid} failed: {e}")

    async def _receive_loop(self):
        """Poll for incoming messages and dispatch them."""
        # The chat hook may not be ready the instant we start (wait_for_ready
        # is False), so wait for its export rather than dying immediately.
        cnt_addr = None
        for _ in range(120):  # ~60s
            cnt_addr = self.client.hook_handler._base_addrs.get("recv_counter")
            if cnt_addr is not None:
                break
            await asyncio.sleep(0.5)
        if cnt_addr is None:
            _log.error("[HiveMind] chat recv hook never became ready; receive loop exiting")
            return
        _log.info("[HiveMind] chat recv hook ready; listening")

        while True:
            try:
                await asyncio.sleep(0.1)

                counter_bytes = await self.client.hook_handler.read_bytes(cnt_addr, 8)
                counter = struct.unpack("<Q", counter_bytes)[0]

                if counter == self._last_counter:
                    continue

                self._last_counter = counter
                sender_gid, message, _ = await self.client.chat_owner.recv_message()

                decoded = self.encoder.decode(message.rstrip())
                if decoded is None:
                    continue  # Not a protocol message, ignore

                msg_type, args = decoded
                # Any protocol message proves the sender is alive.
                if sender_gid in self.peers:
                    self.peers[sender_gid].last_seen = time.monotonic()
                    self.peers[sender_gid].awaiting_ack = False
                _log.info(f"[HiveMind] Received {msg_type.name} from {sender_gid} args={args}")
                await self.dispatcher.dispatch(msg_type, sender_gid, args)

            except asyncio.CancelledError:
                raise
            except Exception as e:
                _log.info(f"[HiveMind] Receive error: {e}")
                await asyncio.sleep(1)

    # ----- handlers -----

    def _record_peer(self, sender_gid: int, args: List[int]) -> PeerInfo:
        """Update (or create) a peer entry from a handshake message's args
        ([role_code, claimed_qx, claimed_qy]). Sets ``bound`` when the
        claimed cell matches the entity we last saw beaconing under this GID."""
        role = Role(args[0]) if args else None
        claimed = (args[1], args[2]) if len(args) >= 3 else None

        peer = self.peers.get(sender_gid)
        if peer is None:
            peer = PeerInfo(gid=sender_gid)
            self.peers[sender_gid] = peer

        peer.role = role
        peer.confirmed = True
        peer.last_seen = time.monotonic()
        if claimed is not None:
            peer.qx, peer.qy = claimed
            seen = self._last_scan_xy.get(sender_gid)
            peer.bound = seen is not None and xy_matches(seen, claimed)
        return peer

    async def _handle_hello(self, sender_gid: int, args: List[int]):
        """Handle incoming HELLO: record the peer and reply HELLO_ACK."""
        peer = self._record_peer(sender_gid, args)
        bound = "bound" if peer.bound else "UNBOUND"
        role_name = peer.role.name if peer.role else "?"
        _log.info(f"[HiveMind] HELLO from {sender_gid} ({role_name}, {bound}); replying HELLO_ACK")
        own_qx, own_qy = await self.discovery.own_quantized_xy()
        await self.send(MessageType.HELLO_ACK, sender_gid, self.role.value, own_qx, own_qy)

    async def _handle_hello_ack(self, sender_gid: int, args: List[int]):
        """Handle incoming HELLO_ACK: the handshake with this peer is complete."""
        peer = self._record_peer(sender_gid, args)
        bound = "bound" if peer.bound else "UNBOUND"
        role_name = peer.role.name if peer.role else "?"
        _log.info(f"[HiveMind] HELLO_ACK from {sender_gid} ({role_name}, {bound}); peer confirmed")

    async def _handle_bot_offer(self, sender_gid: int, args: List[int]):
        """Handle an incoming BOT_OFFER (slave side).

        Auto-reject immediately if we are committed, not seeking, or this
        peer was already declined; otherwise queue it for the user prompt.
        """
        bot_index = args[0] if args else -1
        if self._should_auto_reject(sender_gid):
            reason = ("locked" if self.locked_to is not None
                      else "not seeking" if not self.seeking
                      else "blocklisted")
            _log.info(f"[HiveMind] BOT_OFFER #{bot_index} from {sender_gid} auto-rejected ({reason})")
            await self.send(MessageType.BOT_REJECT, sender_gid, bot_index)
            return
        _log.info(f"[HiveMind] BOT_OFFER #{bot_index} from {sender_gid} -> queued for user prompt")
        await self._offer_queue.put((sender_gid, bot_index))

    async def _handle_bot_accept(self, sender_gid: int, args: List[int]):
        """Handle a slave's BOT_ACCEPT (master side)."""
        bot_index = args[0] if args else -1
        _log.info(f"[HiveMind] {sender_gid} ACCEPTED bot#{bot_index}")
        if self.on_bot_accepted is not None:
            await self.on_bot_accepted(sender_gid, bot_index)

    async def _handle_bot_reject(self, sender_gid: int, args: List[int]):
        """Handle a slave's BOT_REJECT (master side)."""
        bot_index = args[0] if args else -1
        _log.info(f"[HiveMind] {sender_gid} REJECTED bot#{bot_index}")
        if self.on_bot_rejected is not None:
            await self.on_bot_rejected(sender_gid, bot_index)

    async def _handle_keepalive(self, sender_gid: int, args: List[int]):
        """Handle incoming KEEPALIVE: reply KEEPALIVE_ACK echoing the seq."""
        seq = args[0] if args else 0
        await self.send(MessageType.KEEPALIVE_ACK, sender_gid, seq)

    async def _handle_keepalive_ack(self, sender_gid: int, args: List[int]):
        """Handle incoming KEEPALIVE_ACK: liveness is recorded in the recv loop."""
        pass

    async def _handle_session_pause(self, sender_gid: int, args: List[int]):
        """A peer is pausing execution."""
        _log.info(f"[HiveMind] peer {sender_gid} PAUSED")
        if self.on_peer_pause is not None:
            await self.on_peer_pause(sender_gid)

    async def _handle_session_resume(self, sender_gid: int, args: List[int]):
        """A peer is resuming execution."""
        _log.info(f"[HiveMind] peer {sender_gid} RESUMED")
        if self.on_peer_resume is not None:
            await self.on_peer_resume(sender_gid)

    async def _handle_session_end(self, sender_gid: int, args: List[int]):
        """A peer is ending execution: stop coordinating with it."""
        _log.info(f"[HiveMind] peer {sender_gid} ENDED session")
        self._drop_peer(sender_gid)
        if self.on_peer_end is not None:
            await self.on_peer_end(sender_gid)

    async def _handle_session_left(self, sender_gid: int, args: List[int]):
        """A peer is leaving/disconnecting gracefully: forget it."""
        _log.info(f"[HiveMind] peer {sender_gid} LEFT")
        self._drop_peer(sender_gid)
        if self.on_peer_left is not None:
            await self.on_peer_left(sender_gid)

    async def _handle_name(self, sender_gid: int, args: List[int]):
        """Reassemble a peer's wizard name from NAME chunks."""
        if len(args) < 3:
            return
        idx, total, packed = args[0], args[1], args[2]
        parts = self._name_parts.setdefault(sender_gid, {})
        parts[idx] = unpack_chunk(packed)
        if len(parts) >= total and all(i in parts for i in range(total)):
            name = "".join(parts[i] for i in range(total))
            peer = self.peers.get(sender_gid)
            if peer is not None:
                peer.name = name
            _log.info(f"[HiveMind] learned peer name for {sender_gid}: '{name}'")

    async def _handle_ping(self, sender_gid: int, args: List[int]):
        """Handle incoming PING: reply with PONG."""
        _log.info(f"[HiveMind] Got PING from {sender_gid}, sending PONG")
        await self.send(MessageType.PONG, sender_gid)

    async def _handle_pong(self, sender_gid: int, args: List[int]):
        """Handle incoming PONG: log acknowledgement."""
        _log.info(f"[HiveMind] Got PONG from {sender_gid}, peer is alive")
