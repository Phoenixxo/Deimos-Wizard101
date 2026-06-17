"""Collision geometry math for collision-based teleporting.

Mirrors the approach in CIick/QuestWhiz's WorldsCollide.py: build 2D collision and
mesh footprints in a horizontal slice at the target's height, compute the walkable
``free_area = mesh - collisions``, and pick the nearest point inside it (buffered by
the player's radius). Because the chosen point is, by construction, on the walkable
mesh and outside every collision footprint, a teleport to it can't land in a wall —
which is what lets collision TP be a single, first-time-every-time teleport.

The lower-level cube/transform helpers (toCubeVertices, transformCube, toMultidim)
come from PeechezNCreem / CIick and are shared with the shape builders below.
"""

from typing import List, TypeAlias

import numpy as np
from shapely.geometry import Point, Polygon, MultiPolygon
from shapely.ops import unary_union, nearest_points
from wizwalker import XYZ

from .collision import CollisionWorld, ProxyType


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


def build_collision_shapes(world: CollisionWorld, z_slice: float) -> List[Polygon]:
    """Build 2D footprints of solid collision objects that span ``z_slice``.

    Each object is only included when the slice height falls within its vertical
    extent, so geometry above/below the player (e.g. a ceiling) doesn't block.
    """
    shapes = []
    for obj in world.objects:
        try:
            if obj.proxy == ProxyType.BOX:
                l, w, h = obj.params.length, obj.params.width, obj.params.depth
                if obj.location[2] - h / 2 <= z_slice <= obj.location[2] + h / 2:
                    world_pts = transformCube(toCubeVertices((l, w, h)), obj.location, obj.rotation)
                    pts2d = [(p[0], p[1]) for p in world_pts]
                    if len(pts2d) >= 3:
                        shapes.append(Polygon(pts2d).convex_hull)

            elif obj.proxy == ProxyType.SPHERE:
                scale_val = obj.scale if isinstance(obj.scale, (float, int)) else obj.scale[0]
                r = obj.params.radius * scale_val
                if r > 0 and abs(z_slice - obj.location[2]) <= r:
                    shapes.append(Point(obj.location[0], obj.location[1]).buffer(r))

            elif obj.proxy == ProxyType.CYLINDER:
                if isinstance(obj.scale, (float, int)):
                    scale_xy = scale_z = obj.scale
                else:
                    scale_xy, scale_z = obj.scale[0], obj.scale[2]
                scaled_half_length = (obj.params.length / 2) * scale_z
                scaled_radius = obj.params.radius * scale_xy * 0.125
                if scaled_radius > 0 and obj.location[2] - scaled_half_length <= z_slice <= obj.location[2] + scaled_half_length:
                    shapes.append(Point(obj.location[0], obj.location[1]).buffer(scaled_radius))
        except Exception:
            continue
    return shapes


def build_mesh_shapes(world: CollisionWorld, z_slice: float) -> List[Polygon]:
    """Build 2D footprints of the walkable mesh geometry."""
    shapes = []
    for obj in world.objects:
        if obj.proxy == ProxyType.MESH:
            pts3d = transformCube(obj.vertices, obj.location, obj.rotation)
            pts2d = [(x, y) for x, y, z in pts3d]
            if len(pts2d) >= 3:
                shapes.append(Polygon(pts2d).convex_hull)
    return shapes


def find_safe_collision_point(world: CollisionWorld, target: XYZ, player_radius: float, extra_shapes=None):
    """Find the point to teleport to so the player lands on walkable ground, never a wall.

    Works in a 2D slice at ``target.z``. Returns ``(xyz, reason)``:
      - ``(target, "target_clear")``     the target itself clears all collisions,
      - ``(safe_point, "safe_point")``   nearest walkable spot outside the geometry,
      - ``(None, reason)``               not enough collision data to solve safely.

    ``extra_shapes`` are additional collision footprints (e.g. dynamic entity models)
    unioned with the static zone geometry, so the solver routes around them too.

    The returned point is guaranteed to sit on the walkable mesh and at least
    ``player_radius`` away from every collision footprint, so a single teleport to
    it won't clip a wall. Pure CPU work — run off the event loop.
    """
    collision_shapes = filter_valid_polygons(build_collision_shapes(world, target.z))
    if extra_shapes:
        collision_shapes.extend(filter_valid_polygons(extra_shapes))
    mesh_shapes = filter_valid_polygons(build_mesh_shapes(world, target.z))

    if not collision_shapes and not mesh_shapes:
        return None, "no_geometry"

    union_coll = unary_union(collision_shapes) if collision_shapes else Polygon()
    player_at_target = Point(target.x, target.y).buffer(player_radius)

    # If the target footprint is clear of all collisions, go straight there.
    if union_coll.is_empty or not union_coll.intersects(player_at_target):
        return XYZ(target.x, target.y, target.z), "target_clear"

    # Target sits inside collision geometry — find the nearest walkable point outside it.
    union_mesh = unary_union(mesh_shapes) if mesh_shapes else Polygon()
    if union_mesh.is_empty:
        return None, "no_mesh"

    free_area = union_mesh.difference(union_coll)
    if free_area.is_empty:
        return None, "no_free_area"

    # Shrink by the player's radius so the body fits; if that erases the area
    # (target near a tight spot), fall back to the unbuffered free area.
    safe_region = free_area.buffer(-player_radius)
    if safe_region.is_empty:
        safe_region = free_area

    _, candidate = nearest_points(Point(target.x, target.y), safe_region)
    return XYZ(candidate.x, candidate.y, target.z), "safe_point"
