"""Collision geometry math for collision-based teleporting.

Goal: teleport as *close to the target as possible while guaranteeing the spot is
walkable*. We take the real walkable navmesh (the actual triangle faces, not a convex
hull), carve out the wall footprints dilated by the player's clearance, and pick the
point of that region nearest the target. Because the result is on the navmesh and a
clear radius from every wall, the body can't clip — a single, decisive teleport.

(The earlier version hulled the mesh — ~2.3x too big, so it placed teleports in
non-walkable courtyards — and eroded that inflated area by the player radius, which
closed narrow corridors and flung points far from the target. Both are fixed here.)

The lower-level cube/transform helpers (toCubeVertices, transformCube, toMultidim)
come from PeechezNCreem / CIick and are shared with the shape builders below.
"""

import math
from typing import List, TypeAlias

import numpy as np
from shapely.geometry import Point, Polygon, MultiPolygon
from shapely.ops import unary_union, nearest_points
from shapely.prepared import prep
from shapely.strtree import STRtree
from wizwalker import XYZ

from .collision import CollisionWorld, ProxyType, CollisionFlag


Matrix3x3: TypeAlias = tuple[
    float, float, float,
    float, float, float,
    float, float, float,
]

SimpleVert: TypeAlias = tuple[float, float, float]
Vector3D: TypeAlias = tuple[float, float, float]

CubeVertices = tuple[Vector3D, Vector3D, Vector3D, Vector3D, Vector3D, Vector3D, Vector3D, Vector3D]


def cube_to_xyz(cube: list) -> List[XYZ]:
    return [XYZ(v[0], v[1], v[2]) for v in cube]


def subtract_xyz(xyz2: XYZ, xyz1: XYZ) -> XYZ:
    # b - a = (bx - ax, by - ay, bz - az)
    return XYZ((xyz2.x - xyz1.x), (xyz2.y - xyz1.y), (xyz2.z - xyz1.z))


def multiply_xyz(a: XYZ, b: XYZ) -> float:
    # a dot b = ax*bx + ay*by + az*bz
    return a.x * b.x + a.y * b.y + a.z * b.z


def toCubeVertices(dimensions: Vector3D) -> CubeVertices:
    l, w, d = dimensions
    l /= 2
    w /= 2
    d /= 2
    return (
        (-l, -w, -d),
        (l, -w, -d),
        (l, -w, d),
        (-l, -w, d),

        (-l, w, -d),
        (l, w, -d),
        (l, w, d),
        (-l, w, d),
    )


def toMultidim(mat: Matrix3x3):
    # Transposed: the cubes come out distorted otherwise.
    return (
        (mat[0], mat[3], mat[6]),
        (mat[1], mat[4], mat[7]),
        (mat[2], mat[5], mat[8]),
    )


def transformCube(cube, location, rotation):
    tpoints = [np.dot((p,), toMultidim(rotation))[0] for p in cube]
    for p in tpoints:
        p[0] += location[0]
        p[1] += location[1]
        p[2] += location[2]
    return tpoints


def filter_valid_polygons(shapes) -> List[Polygon]:
    """Keep only non-empty 2D Polygons, flattening MultiPolygons.

    Degenerate inputs (collinear vertices) can make ``.convex_hull`` return a
    LineString or Point; those would break ``unary_union``/``difference``, so we
    drop them here.
    """
    valid = []
    for shape in shapes:
        if shape is None or shape.is_empty:
            continue
        if shape.geom_type == "Polygon":
            valid.append(shape)
        elif shape.geom_type == "MultiPolygon":
            valid.extend(poly for poly in shape.geoms if poly.geom_type == "Polygon")
    return valid


# A teleport target's z is the player's *feet*. A collider blocks the spot when its
# vertical extent overlaps a thin slack band around the feet, ``[z - Z_BAND_DOWN,
# z + Z_BAND_UP]`` — not the player's full visual height. Walls in collision.bcd run
# from ~ground level upward, so this catches them (including ones whose modeled base
# floats a little above the navmesh, e.g. WC Triton's central cylinder sits ~4u high),
# while overhead structures the player walks *under* (domes, arches, upper-floor walls
# — bases 75–270u up) are correctly ignored. A full body-height band over-blocks those
# and throws teleports wildly past them; a foot-only point slice misses the floating-
# base walls and clips. ~50u of upward slack threads that needle.
#
# A real wall always rises *above* the feet (high zmax), so it's caught regardless of
# how far down the band reaches; the only thing Z_BAND_DOWN includes is colliders whose
# TOP is below the feet — sub-floor foundation/water volumes (e.g. GH MainHub's dock
# cylinders, r~447 at z ending ~13u under the surface). Too much downward slack lets one
# of those wipe out the walkable dock around it and throw a teleport hundreds of units
# off. Keep it small — just enough for a wall whose base is modeled a hair below the
# navmesh — so genuinely-underfoot geometry is ignored.
Z_BAND_UP = 50.0
Z_BAND_DOWN = 8.0


def _z_overlaps(obj_zmin: float, obj_zmax: float, band_lo: float, band_hi: float) -> bool:
    """Whether an object's vertical extent overlaps the foot-level slack band."""
    return obj_zmin <= band_hi and obj_zmax >= band_lo


def build_collision_shapes(world: CollisionWorld, z_slice: float) -> List[Polygon]:
    """Build 2D footprints of solid collision objects at the player's foot level.

    An object is included when its vertical extent overlaps the slack band
    ``[z_slice - Z_BAND_DOWN, z_slice + Z_BAND_UP]``, so a ground wall (even one whose
    modeled base floats slightly above the feet) blocks while overhead geometry the
    player walks under does not.
    """
    band_lo = z_slice - Z_BAND_DOWN
    band_hi = z_slice + Z_BAND_UP
    shapes = []
    for obj in world.objects:
        try:
            scale_val = obj.scale if isinstance(obj.scale, (float, int)) else obj.scale[0]
            if obj.proxy == ProxyType.BOX:
                # Box dimensions are intentionally left unscaled (the stored transform
                # may already encode scale); only the slice test changed to a band.
                l, w, h = obj.params.length, obj.params.width, obj.params.depth
                if _z_overlaps(obj.location[2] - h / 2, obj.location[2] + h / 2, band_lo, band_hi):
                    world_pts = transformCube(toCubeVertices((l, w, h)), obj.location, obj.rotation)
                    pts2d = [(p[0], p[1]) for p in world_pts]
                    if len(pts2d) >= 3:
                        shapes.append(Polygon(pts2d).convex_hull)

            elif obj.proxy == ProxyType.SPHERE:
                r = obj.params.radius * scale_val
                if r > 0 and _z_overlaps(obj.location[2] - r, obj.location[2] + r, band_lo, band_hi):
                    shapes.append(Point(obj.location[0], obj.location[1]).buffer(r))

            elif obj.proxy == ProxyType.CYLINDER:
                # Collision cylinders store a true world-space radius (median ~500 in
                # WC — these are building-sized volumes). A previous ``* 0.125`` fudge
                # shrank them to ~1/8, so teleports could land *inside* a building.
                r = obj.params.radius * scale_val
                half_len = (obj.params.length / 2) * scale_val
                if r > 0 and _z_overlaps(obj.location[2] - half_len, obj.location[2] + half_len, band_lo, band_hi):
                    shapes.append(Point(obj.location[0], obj.location[1]).buffer(r))
        except Exception:
            continue
    return shapes


# Unioned walkable navmesh per zone. Building it from the raw triangles (~15k in a
# big zone) costs ~1.5s, and it never changes within a session, so we memoize it.
_navmesh_cache: dict[str, object] = {}


def build_mesh_shapes(world: CollisionWorld, z_slice: float | None = None) -> List[Polygon]:
    """Build the *real* walkable navmesh footprints (actual triangle faces).

    This used to take the convex hull of each mesh proxy, which over-stated the
    walkable area ~2.3x — filling in building interiors, fountains and courtyards
    that aren't walkable. The solver then happily placed teleports in that fake
    area (and the inflated mesh, eroded by the player radius, threw points far from
    the target). We now union the actual WALKABLE triangle faces, i.e. the game's
    true walkable surface. ``z_slice`` is unused (the mesh is taken whole) but kept
    for signature compatibility.
    """
    shapes = []
    for obj in world.objects:
        if obj.proxy == ProxyType.MESH and CollisionFlag.WALKABLE in obj.category_flags:
            pts3d = transformCube(obj.vertices, obj.location, obj.rotation)
            tris = []
            for face in obj.faces:
                a, b, c = face
                try:
                    tri = Polygon([
                        (pts3d[a][0], pts3d[a][1]),
                        (pts3d[b][0], pts3d[b][1]),
                        (pts3d[c][0], pts3d[c][1]),
                    ])
                    if tri.is_valid and tri.area > 0:
                        tris.append(tri)
                except Exception:
                    continue
            if tris:
                # Merge each proxy's own faces once; far cheaper than a single
                # global union of every triangle in the zone.
                shapes.append(unary_union(tris))
    return shapes


def _walkable_union(world: CollisionWorld, zone_name: str | None):
    """The unioned walkable navmesh polygon, memoized per zone."""
    if zone_name is not None:
        cached = _navmesh_cache.get(zone_name)
        if cached is not None:
            return cached
    shapes = filter_valid_polygons(build_mesh_shapes(world))
    union = unary_union(shapes) if shapes else Polygon()
    if zone_name is not None:
        _navmesh_cache[zone_name] = union
    return union


def _walkable_minus_walls(union_mesh, union_coll, player_radius: float):
    """Navmesh with walls (dilated by the player's clearance) carved out.

    Dilating the *walls* and subtracting them — rather than eroding the whole free
    area — keeps the navmesh's own outer edges intact (you can still stand at the
    lip of a platform) while guaranteeing the body clears every wall. If full
    clearance leaves nothing reachable (a genuinely tight spot), the clearance is
    relaxed step-wise rather than failing outright: a snug landing beats none.
    """
    if union_coll.is_empty:
        return union_mesh
    for clearance in (player_radius, player_radius * 0.5, 0.0):
        carved = union_coll.buffer(clearance) if clearance > 0 else union_coll
        region = union_mesh.difference(carved)
        if not region.is_empty:
            return region
    return None


# Per-zone spatial index of walkable triangles (with their surface z), for sampling
# the ground height at an arbitrary (x, y) during the teleport-march.
_navmesh_index_cache: dict[str, tuple] = {}


def _navmesh_index(world: CollisionWorld, zone_name: str | None):
    """``(STRtree, [triangle], [centroid_z])`` over the walkable faces, memoized per zone."""
    if zone_name is not None and zone_name in _navmesh_index_cache:
        return _navmesh_index_cache[zone_name]
    tris, zs = [], []
    for obj in world.objects:
        if obj.proxy == ProxyType.MESH and CollisionFlag.WALKABLE in obj.category_flags:
            pts3d = transformCube(obj.vertices, obj.location, obj.rotation)
            for a, b, c in obj.faces:
                try:
                    tri = Polygon([
                        (pts3d[a][0], pts3d[a][1]),
                        (pts3d[b][0], pts3d[b][1]),
                        (pts3d[c][0], pts3d[c][1]),
                    ])
                    if tri.is_valid and tri.area > 0:
                        tris.append(tri)
                        zs.append((pts3d[a][2] + pts3d[b][2] + pts3d[c][2]) / 3.0)
                except Exception:
                    continue
    tree = STRtree(tris) if tris else None
    result = (tree, tris, zs)
    if zone_name is not None:
        _navmesh_index_cache[zone_name] = result
    return result


def closest_walkable_along(world: CollisionWorld, zone_name: str | None, start_xyz: XYZ,
                           target_xyz: XYZ, player_radius: float, extra_shapes=None,
                           step: float = 60.0, max_steps: int = 80):
    """Furthest *validated-walkable* point from ``start_xyz`` toward ``target_xyz``.

    The walkable region is the navmesh minus walls (collisions dilated by
    ``player_radius``). ``extra_shapes`` are additional collider footprints — the zone's
    static entity objects (NPCs, props, teleporters from gamedata.bin) — unioned with the
    collision.bcd geometry, so the march routes around them too (e.g. it won't land you
    on top of the UniverseTeleport). ``start_xyz`` comes from an A* anchor on ``zone.nav``,
    which can disagree with ``collision.bcd`` and sit inside a wall — so we first **snap**
    it onto the walkable region, then march the straight XY line toward the target in
    ``step`` increments, keeping each point that stays walkable and stopping at the first
    blocked step. Surface z is sampled from the navmesh triangle nearest the running height
    (so a ground march doesn't snap onto an overhead level).

    Always returns a point that is on the walkable region (at minimum the snapped start),
    so the caller can teleport to it without landing in a wall. Returns ``None`` only when
    there's no navmesh/walkable area at all (caller should defer to navmap). Pure CPU.
    """
    tree, tris, zs = _navmesh_index(world, zone_name)
    if tree is None:
        return None
    mesh = _walkable_union(world, zone_name)
    if mesh.is_empty:
        return None
    coll_shapes = filter_valid_polygons(build_collision_shapes(world, start_xyz.z))
    if extra_shapes:
        coll_shapes.extend(filter_valid_polygons(extra_shapes))
    union_coll = unary_union(coll_shapes) if coll_shapes else None
    if union_coll is not None and not union_coll.is_empty:
        walkable_region = mesh.difference(union_coll.buffer(player_radius))
    else:
        walkable_region = mesh
    if walkable_region.is_empty:
        return None
    in_walkable = prep(walkable_region)

    def surface_z(x: float, y: float, ref_z: float):
        pt = Point(x, y)
        best_z, best_dz = None, None
        for i in tree.query(pt):
            tri = tris[i]
            if tri.contains(pt) or tri.touches(pt):
                dz = abs(zs[i] - ref_z)
                if best_dz is None or dz < best_dz:
                    best_dz, best_z = dz, zs[i]
        return best_z

    # Snap the (possibly-in-a-wall) A* anchor onto walkable ground before marching.
    start_pt = Point(start_xyz.x, start_xyz.y)
    if not in_walkable.contains(start_pt):
        _, start_pt = nearest_points(start_pt, walkable_region)

    ref_z = surface_z(start_pt.x, start_pt.y, start_xyz.z)
    if ref_z is None:
        ref_z = start_xyz.z
    best = XYZ(start_pt.x, start_pt.y, ref_z)

    dx, dy = target_xyz.x - start_pt.x, target_xyz.y - start_pt.y
    total = math.hypot(dx, dy)
    if total < 1e-6:
        return best
    ux, uy = dx / total, dy / total
    d = step
    steps = 0
    while d < total and steps < max_steps:
        x, y = start_pt.x + ux * d, start_pt.y + uy * d
        if not in_walkable.contains(Point(x, y)):
            break
        z = surface_z(x, y, ref_z)
        if z is None:
            break
        best = XYZ(x, y, z)
        ref_z = z
        d += step
        steps += 1
    # If the target itself is walkable, finish exactly on it.
    if in_walkable.contains(Point(target_xyz.x, target_xyz.y)):
        z = surface_z(target_xyz.x, target_xyz.y, ref_z)
        if z is not None:
            best = XYZ(target_xyz.x, target_xyz.y, z)
    return best


def find_safe_collision_point(world: CollisionWorld, target: XYZ, player_radius: float,
                              extra_shapes=None, zone_name: str | None = None):
    """The point *closest* to ``target`` that is walkable and clear of walls.

    Returns ``(xyz, reason)``:
      - ``(target, "target_clear")``    target is already walkable & wall-clear,
      - ``(safe_point, "safe_point")``  nearest walkable point with wall clearance,
      - ``(None, reason)``              no navmesh / nothing walkable to land on.

    Walls (zone collision footprints + ``extra_shapes`` static colliders) are dilated
    by ``player_radius`` and subtracted from the real walkable navmesh, so the result
    is on walkable ground, keeps the body off every wall, and is as close to ``target``
    as the geometry allows. ``zone_name`` enables the per-zone navmesh cache. Pure CPU
    work — run off the event loop.
    """
    union_mesh = _walkable_union(world, zone_name)
    if union_mesh.is_empty:
        return None, "no_mesh"

    collision_shapes = filter_valid_polygons(build_collision_shapes(world, target.z))
    if extra_shapes:
        collision_shapes.extend(filter_valid_polygons(extra_shapes))
    union_coll = unary_union(collision_shapes) if collision_shapes else Polygon()

    walkable = _walkable_minus_walls(union_mesh, union_coll, player_radius)
    if walkable is None or walkable.is_empty:
        return None, "no_walkable"

    tp = Point(target.x, target.y)
    if walkable.contains(tp):
        return XYZ(target.x, target.y, target.z), "target_clear"

    _, candidate = nearest_points(tp, walkable)
    return XYZ(candidate.x, candidate.y, target.z), "safe_point"


def find_safe_magic_grid_points(
    world: CollisionWorld,
    target: XYZ,
    player_radius: float,
    factor: float,
    extra_shapes=None,
    zone_name: str | None = None,
    limit: int = 8,
):
    """Up to ``limit`` **magic-grid** points that are walkable and clear of
    collisions, **ranked nearest-to-``target`` first**.

    Same geometry as ``find_safe_magic_grid_point`` (the single-point version is
    just ``[0]`` of this), but returns a ranked shortlist so the caller can fall
    through to the next candidate when a teleport is rubber-banded back. That
    happens for colliders the file model can't see — notably warp/teleporter
    trigger volumes (e.g. ``AZ-TELEPORT-…``), which carry no
    ``m_solidCollisionFilename`` yet still bounce you — so geometric clearance
    alone can't guarantee a landing; the caller verifies empirically and retries.

    Returns ``(xyz_list, reason)``:
      - ``(grid_xyz_list, "magic_grid")``  ranked on-grid points inside the
        walkable region (buffered by ``player_radius``); may be length 1,
      - ``([], reason)``                    no geometry / no on-grid point fits.

    Pure CPU work (shapely) — run off the event loop.
    """
    union_mesh = _walkable_union(world, zone_name)
    if union_mesh.is_empty:
        return [], "no_mesh"

    collision_shapes = filter_valid_polygons(build_collision_shapes(world, target.z))
    if extra_shapes:
        collision_shapes.extend(filter_valid_polygons(extra_shapes))
    union_coll = unary_union(collision_shapes) if collision_shapes else Polygon()

    safe_region = _walkable_minus_walls(union_mesh, union_coll, player_radius)
    if safe_region is None or safe_region.is_empty:
        return [], "no_walkable"

    # Enumerate grid intersections within the region's bounds, keep those inside
    # the walkable region, and sort by distance to the target. Bounds are
    # (minx, miny, maxx, maxy) in the horizontal plane (shapely y == world y here).
    minx, miny, maxx, maxy = safe_region.bounds
    ix0, ix1 = math.ceil(minx / factor), math.floor(maxx / factor)
    iy0, iy1 = math.ceil(miny / factor), math.floor(maxy / factor)

    candidates = []
    for ix in range(ix0, ix1 + 1):
        px = ix * factor
        for iy in range(iy0, iy1 + 1):
            py = iy * factor
            if safe_region.contains(Point(px, py)):
                dist_sq = (px - target.x) ** 2 + (py - target.y) ** 2
                candidates.append((dist_sq, px, py))

    if not candidates:
        return [], "no_grid_point"
    candidates.sort(key=lambda c: c[0])
    points = [XYZ(px, py, target.z) for _d, px, py in candidates[:limit]]
    return points, "magic_grid"


def find_safe_magic_grid_point(
    world: CollisionWorld,
    target: XYZ,
    player_radius: float,
    factor: float,
    extra_shapes=None,
    zone_name: str | None = None,
):
    """Nearest **magic-grid** point that is walkable and clear of collisions.

    Thin wrapper over ``find_safe_magic_grid_points`` returning only the single
    closest point as ``(xyz, reason)`` (or ``(None, reason)``). Prefer the plural
    form when you can verify-and-retry, so an unmodeled warp volume doesn't strand
    you. Pure CPU work (shapely) — run off the event loop.
    """
    points, reason = find_safe_magic_grid_points(
        world, target, player_radius, factor,
        extra_shapes=extra_shapes, zone_name=zone_name, limit=1,
    )
    if not points:
        return None, reason
    return points[0], reason
