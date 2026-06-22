"""Peer discovery over the entity list.

When a bot activates HiveMind it does two things that together mark it,
unmistakably, as a fellow exploiter to anyone scanning the area:

  1. It teleports to the nearest **magic grid** point -- the closest
     position whose two horizontal coordinates are *both* integer
     multiples of MAGIC_FACTOR (e.g. 1024), including 0. A legit player
     reaching such a point by chance is statistically negligible.
  2. It writes a reserved **beacon yaw** to its own body encoding its
     role (master vs slave).

The server replicates both position and orientation to every nearby
client, so a scanning bot walks its own entity list, filters to
"Player Object" entities, and accepts a peer only when it satisfies
*both* conditions: on the magic grid AND facing a role yaw. Either
signal alone is insufficient -- a legit player can stand anywhere, and a
coincidental yaw without the grid position doesn't qualify either.

Coordinate convention: WizWalker XYZ is **Z-up** -- ``.x`` and ``.y`` form
the horizontal ground plane and ``.z`` is height. The magic grid is
applied to the horizontal plane (``.x``, ``.y``); height (``.z``) is left
for the game to snap to terrain on teleport. (The project spec calls
these the "X and Z" axes -- those are the two *horizontal* axes, i.e.
WizWalker ``.x`` and ``.y``; the spec's vertical "Y" is WizWalker ``.z``.)
"""

import asyncio
import logging
from dataclasses import dataclass
from enum import Enum
from typing import Awaitable, Callable, List, Optional, Sequence, Tuple, Union

from wizwalker import XYZ
from wizwalker.errors import MemoryReadError

_log = logging.getLogger("hivemind")


class Role(Enum):
    """A bot's role in the hive. Advertised via its beacon yaw."""
    MASTER = 0
    SLAVE = 1


# Reserved "magic" yaw values (radians, within the natural 0..2*pi range).
# A bot writes one of these to its own body to advertise presence + role.
# They are spaced far apart so an epsilon match is unambiguous.
MASTER_YAW = 2.7182818      # e
SLAVE_YAW = 3.1415926       # pi
# A third reserved value, not tied to a role -- used for message
# confirmation beacons and future signalling as the protocol grows.
CONFIRM_YAW = 1.6180339     # phi

_ROLE_YAWS = {
    Role.MASTER: MASTER_YAW,
    Role.SLAVE: SLAVE_YAW,
}

# How close a read yaw must be to a sentinel to count as that beacon. The
# server quantizes replicated orientation, so the yaw a *peer* observes is only
# approximately what we wrote -- this window must absorb that. The role yaws are
# ~0.42 rad apart, so anything well under ~0.2 keeps master/slave distinct. The
# magic-grid position + DM handshake are the real authenticators, so a generous
# yaw window is safe.
YAW_EPSILON = 0.08

# The magic grid spacing (world units). On activation a bot snaps its
# horizontal position to the nearest multiple of this; discovery only
# considers peers sitting on the grid. Larger => rarer to hit by accident.
MAGIC_FACTOR = 1024.0

# Slack (world units) when testing whether a replicated position is "on the
# grid". In practice a teleported bot replicates at *exactly* a multiple
# (observed grid_off == 0.0), so this is kept tight: it only needs to absorb
# the odd unit of jitter, while shrinking the chance a wandering player lands
# here. On-grid area = (2*MAGIC_TOLERANCE / MAGIC_FACTOR)^2 -- at 6.0 that's
# ~0.014% of positions (vs ~0.4% at 32), before the stationary + handshake gates.
MAGIC_TOLERANCE = 6.0

# A beacon bot teleports onto the grid and stands perfectly still; a walking
# player only clips a cell in passing. So we require a candidate's position to
# be unchanged (within this many units) across consecutive scans before we treat
# it as a peer -- this filters out players merely crossing a grid point.
STILL_EPSILON = 1.0

# After teleporting onto a grid point we let the server settle, then read the
# position back to confirm it *stuck*. The collision solver only knows the
# modeled geometry (collision.bcd + gamedata.bin solid colliders); warp/teleporter
# trigger volumes carry no solid-collision file yet still rubber-band you, so a
# geometrically-clear point can still be rejected. We detect that empirically and
# fall through to the next-nearest candidate.
_TELEPORT_SETTLE = 1.0       # seconds to wait before reading position back
# A successful landing keeps our horizontal X/Y on the requested point (only Z
# terrain-snaps); a rubber-band throws us hundreds of units away. This window is
# wide enough to absorb terrain snap / server quantization yet far below a bounce.
_LANDED_TOLERANCE = 48.0

# Slack (in grid cells) when matching a peer's claimed cell against the
# entity we see, to absorb rounding at a cell boundary.
CELL_TOLERANCE = 1

# The object_name() every player avatar shares.
PLAYER_OBJECT_NAME = "Player Object"

# Optional injected resolver: ``async (client) -> XYZ | [XYZ, ...]`` returning
# *walkable* magic-grid point(s). Deimos supplies one backed by its collision
# math (snap the horizontal plane to MAGIC_FACTOR, but only to points that clear
# the zone's collision geometry). Returning a list — ranked nearest-first — lets
# ``activate``/``repin`` fall through to the next candidate when a teleport is
# rubber-banded off an unmodeled collider. Without a resolver we fall back to the
# plain nearest-multiple snap, which ignores walls.
GridResolver = Callable[[object], Awaitable[Union[None, XYZ, Sequence[XYZ]]]]


def quantize(value: float) -> int:
    """Quantize a horizontal coordinate to its magic-grid cell index."""
    return int(round(value / MAGIC_FACTOR))


def quantize_xy(position: XYZ) -> Tuple[int, int]:
    """Quantize the horizontal plane (.x, .y) to magic-grid cell indices."""
    return quantize(position.x), quantize(position.y)


def nearest_magic_point(position: XYZ) -> XYZ:
    """The closest on-grid position: ``.x`` and ``.y`` snapped to multiples
    of MAGIC_FACTOR, height (``.z``) preserved (the game terrain-snaps it)."""
    return XYZ(
        x=quantize(position.x) * MAGIC_FACTOR,
        y=quantize(position.y) * MAGIC_FACTOR,
        z=position.z,
    )


def is_on_magic_grid(x: float, y: float, tolerance: float = MAGIC_TOLERANCE) -> bool:
    """True if both horizontal coords sit within ``tolerance`` of a MAGIC_FACTOR multiple."""
    off_x = abs(x - quantize(x) * MAGIC_FACTOR)
    off_y = abs(y - quantize(y) * MAGIC_FACTOR)
    return off_x <= tolerance and off_y <= tolerance


def role_for_yaw(yaw: float) -> Optional[Role]:
    """Return the Role a yaw advertises, or None if it is not a beacon."""
    for role, sentinel in _ROLE_YAWS.items():
        if abs(yaw - sentinel) <= YAW_EPSILON:
            return role
    return None


def is_confirm_yaw(yaw: float) -> bool:
    """True if a yaw matches the reserved confirmation/utility beacon."""
    return abs(yaw - CONFIRM_YAW) <= YAW_EPSILON


def xy_matches(a: Tuple[int, int], b: Tuple[int, int], tolerance: int = CELL_TOLERANCE) -> bool:
    """True if two grid cells are within ``tolerance`` cells of each other."""
    return abs(a[0] - b[0]) <= tolerance and abs(a[1] - b[1]) <= tolerance


@dataclass
class PeerBeacon:
    """A peer spotted in the entity list: a Player Object sitting on the magic
    grid. (Yaw is NOT used -- a memory yaw write doesn't replicate to other
    clients, only position does, so the magic-grid position is the signal and
    the DM handshake is the authenticator.)"""
    gid: int
    qx: int   # horizontal magic-grid cell index (x / MAGIC_FACTOR)
    qy: int   # horizontal magic-grid cell index (y / MAGIC_FACTOR)
    location: XYZ
    distance: float


class HiveMindDiscovery:
    """Advertises this client and scans the entity list for peers.

    Wraps a WizWalker client. ``activate`` teleports onto the magic grid
    and writes the role beacon yaw; ``repin`` re-asserts that position/yaw
    (the hold loop); ``scan`` returns the peers currently visible (on-grid
    AND beaconing a role yaw).
    """

    def __init__(self, client, grid_resolver: Optional[GridResolver] = None):
        self.client = client
        self.role: Optional[Role] = None
        self.grid_resolver = grid_resolver
        # Last-scan position of each on-grid candidate, for the stationary check.
        self._last_seen_pos: dict = {}

    async def own_gid(self) -> int:
        """This client's GID, read from the *same* field as peers' GIDs
        (``character_id``) so self-exclusion compares like with like."""
        return await self.client.client_object.character_id()

    async def own_address(self) -> int:
        """Memory address of our own player object, for reliable self-exclusion."""
        return await self.client.client_object.read_base_address()

    async def own_quantized_xy(self) -> Tuple[int, int]:
        """Our own horizontal position as a magic-grid cell index pair."""
        position = await self.client.body.position()
        return quantize_xy(position)

    async def visible_player_gids(self) -> set:
        """GIDs of all Player Object entities currently readable in our list.

        A peer whose GID is in this set is in range (and thus self-evidently
        online); used by the range-driven keepalive check. Unlike ``scan``
        this does not require the peer to be on the grid or beaconing -- it
        only asks "can we still see this avatar?"
        """
        try:
            own_addr = await self.own_address()
        except MemoryReadError:
            own_addr = 0
        gids = set()
        for entity in await self.client.get_base_entity_list():
            try:
                if await entity.read_base_address() == own_addr:
                    continue
                if await entity.object_name() != PLAYER_OBJECT_NAME:
                    continue
                gid = await entity.character_id()
                if gid:
                    gids.add(gid)
            except MemoryReadError:
                continue
        return gids

    async def _grid_targets(self) -> List[XYZ]:
        """Resolve candidate grid points to teleport to, ranked nearest-first.

        Uses the injected resolver (which may return a single XYZ or a ranked
        list of walkable on-grid points); falls back to the plain nearest grid
        multiple when no resolver is wired or it yields nothing.
        """
        if self.grid_resolver is not None:
            result = await self.grid_resolver(self.client)
            if isinstance(result, XYZ):
                return [result]
            if result:  # a non-empty sequence
                return list(result)
        return [nearest_magic_point(await self.client.body.position())]

    async def _teleport_onto_grid(self, role: Role) -> bool:
        """Teleport onto a grid point and confirm the server accepted it.

        Tries each candidate nearest-first: teleport, let the server settle, then
        read the position back. A geometrically-clear point can still be rejected
        by an unmodeled collider (a warp/teleporter trigger volume bounces you even
        with no solid-collision file), so we verify the landing stuck and otherwise
        fall through to the next candidate. Returns True once a teleport sticks.

        On a total miss (no candidate sticks, or the teleport hook isn't ready) we
        at least write the beacon yaw in place so discovery still works if we happen
        to already be on the grid.
        """
        targets = await self._grid_targets()
        for i, target in enumerate(targets):
            try:
                await self.client.teleport(target, yaw=_ROLE_YAWS[role])
            except Exception as e:
                _log.warning(f"[HiveMind] grid teleport failed ({e}); writing beacon yaw in place")
                await self.client.body.write_yaw(_ROLE_YAWS[role])
                return False
            await asyncio.sleep(_TELEPORT_SETTLE)
            try:
                pos = await self.client.body.position()
            except MemoryReadError:
                # Can't confirm; assume it took rather than thrash.
                return True
            off = ((pos.x - target.x) ** 2 + (pos.y - target.y) ** 2) ** 0.5
            if off <= _LANDED_TOLERANCE:
                _log.info(
                    f"[HiveMind] grid teleport landed ({target.x:.1f},{target.y:.1f}) "
                    f"off={off:.1f} cand={i + 1}/{len(targets)}"
                )
                return True
            _log.info(
                f"[HiveMind] grid teleport bounced ({target.x:.1f},{target.y:.1f}) "
                f"off={off:.1f}; trying next candidate ({i + 1}/{len(targets)} used)"
            )
        _log.warning(
            f"[HiveMind] no grid candidate stuck ({len(targets)} tried); "
            f"writing beacon yaw in place"
        )
        try:
            await self.client.body.write_yaw(_ROLE_YAWS[role])
        except Exception:
            pass
        return False

    async def activate(self, role: Role):
        """Join the hive: teleport onto the nearest *walkable* magic-grid point
        that the server accepts and write ``role``'s beacon yaw. Verifies the
        landing stuck and falls through to the next-nearest grid point if the
        game rubber-bands us off an unmodeled collider.

        Requires the movement teleport hook (set up by client.activate_hooks()).
        """
        self.role = role
        _log.info(f"[HiveMind] activate {role.name}: teleporting onto grid")
        await self._teleport_onto_grid(role)

    async def repin(self):
        """Re-teleport onto the grid and re-assert the beacon yaw.

        Used by the hold loop to keep the bot pinned in place/orientation
        (e.g. against knockback) while the team assembles. No-op until a
        role has been set via ``activate``/``set_beacon``.
        """
        if self.role is None:
            return
        await self._teleport_onto_grid(self.role)

    async def set_beacon(self, role: Role):
        """Write ``role``'s beacon yaw without moving.

        Use ``activate`` for the full join (teleport + beacon); this is for
        callers that have already positioned the bot on the magic grid.
        """
        self.role = role
        await self.client.body.write_yaw(_ROLE_YAWS[role])

    async def write_confirm_beacon(self):
        """Write the reserved confirmation/utility yaw to our body.

        Reserved for message-confirmation and future signalling; not tied
        to a role.
        """
        await self.client.body.write_yaw(CONFIRM_YAW)

    async def scan(self) -> List[PeerBeacon]:
        """Return peers currently visible in the entity list.

        A peer is a "Player Object" (not us) sitting on the magic grid. Position
        replicates reliably; yaw does not, so it isn't used. The DM handshake
        authenticates the sighting. Transient per-entity read errors are skipped.
        """
        own_gid = await self.own_gid()
        try:
            own_addr = await self.own_address()
        except MemoryReadError:
            own_addr = 0
        try:
            own_position = await self.client.body.position()
        except MemoryReadError:
            own_position = None

        n_players = n_skip_grid = n_skip_moving = 0
        seen_now: dict = {}
        peers: List[PeerBeacon] = []
        for entity in await self.client.get_base_entity_list():
            try:
                # Never treat ourselves as a peer.
                if await entity.read_base_address() == own_addr:
                    continue
                if await entity.object_name() != PLAYER_OBJECT_NAME:
                    continue
                n_players += 1

                location = await entity.location()
                gid = await entity.character_id()
                off_x = abs(location.x - quantize(location.x) * MAGIC_FACTOR)
                off_y = abs(location.y - quantize(location.y) * MAGIC_FACTOR)
                on_grid = is_on_magic_grid(location.x, location.y)

                if not on_grid:
                    _log.info(f"[HiveMind] scan: gid={gid} on_grid=False grid_off=({off_x:.1f},{off_y:.1f})")
                    n_skip_grid += 1
                    continue

                # Stationary check: a beacon stands still; a walker clipping the
                # cell will have moved since last scan. Record position either way.
                prev = self._last_seen_pos.get(gid)
                seen_now[gid] = (location.x, location.y)
                stationary = prev is not None and abs(location.x - prev[0]) <= STILL_EPSILON and abs(location.y - prev[1]) <= STILL_EPSILON
                _log.info(
                    f"[HiveMind] scan: gid={gid} on_grid=True stationary={stationary} "
                    f"pos=({location.x:.1f},{location.y:.1f})"
                )

                if not stationary:
                    n_skip_moving += 1
                    continue
                if gid == 0 or gid == own_gid:
                    continue

                qx, qy = quantize_xy(location)
                if own_position is not None:
                    dx = location.x - own_position.x
                    dy = location.y - own_position.y
                    dz = location.z - own_position.z
                    distance = (dx * dx + dy * dy + dz * dz) ** 0.5
                else:
                    distance = float("inf")

                peers.append(
                    PeerBeacon(gid=gid, qx=qx, qy=qy, location=location, distance=distance)
                )
            except MemoryReadError:
                continue  # entity churned mid-read; skip it

        # Remember on-grid positions for the next scan's stationary comparison.
        self._last_seen_pos = seen_now
        _log.info(
            f"[HiveMind] scan summary: {n_players} player objs, {len(peers)} stationary on-grid peer(s) "
            f"(off_grid={n_skip_grid}, moving={n_skip_moving}); own_gid={own_gid}"
        )
        return peers
