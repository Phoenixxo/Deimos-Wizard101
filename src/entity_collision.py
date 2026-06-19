import json
import os
import re
import threading
from pathlib import Path

from loguru import logger
from shapely.affinity import rotate, scale, translate
from shapely.geometry import MultiPoint, Point, Polygon
from wizwalker.utils import get_wiz_install

# katsuba + kinif + wiztype are best-effort: if any is missing we degrade to
# bounding-box entity collision rather than breaking collision TP entirely.
try:
    import kinif
    import wiztype
    from katsuba.op import (
        STATEFUL_FLAGS,
        LazyList,
        LazyObject,
        Serializer,
        SerializerOptions,
        TypeList,
    )
    from katsuba.wad import Archive

    _PRECISE_AVAILABLE = True
except Exception:  # pragma: no cover - import-time capability probe
    _PRECISE_AVAILABLE = False

# WADs to search for a model whose asset path has no |Source| prefix.
_FALLBACK_WADS = [
    "Mob-WorldData.wad",
    "Mob2-WorldData.wad",
    "_Shared-WorldData.wad",
    "Root.wad",
]

# Bounding-circle radius for a static object whose model can't be resolved to a
# footprint (e.g. the Universe teleport, which only references a blank-character
# placeholder NIF). Big enough to keep a teleport off the object, small enough not to
# wall off the area around it.
_DEFAULT_STATIC_RADIUS = 150.0


def _footprint_cache_path(revision: str) -> Path:
    """Writable, per-revision footprint cache location (alongside Deimos settings)."""
    appdata = os.environ.get("APPDATA", "")
    base = Path(appdata) / "Deimos" if appdata else Path(os.getcwd())
    return base / "footprint_cache" / (revision.replace(".", "_") + ".json")


def _typelist_cache_path(revision: str) -> Path:
    """Writable, per-revision katsuba TypeList location (alongside Deimos settings)."""
    appdata = os.environ.get("APPDATA", "")
    base = Path(appdata) / "Deimos" if appdata else Path(os.getcwd())
    return base / "types" / (revision.replace(".", "_") + ".json")


def _typelist_is_loadable(path: Path) -> bool:
    """Cheap validity probe: the cached dump exists, is non-empty, and katsuba can
    open it. Catches a corrupt/half-written cache so we re-dump instead of choking."""
    try:
        return path.exists() and path.stat().st_size > 0 and bool(TypeList.open(str(path)))
    except Exception:
        return False


def _dump_type_list(revision: str, path: Path) -> None:
    """Pull a fresh type dump from the running client and write it to ``path`` (atomic).

    Requires a live WizardGraphicalClient. Raises with an actionable message when
    wiztype can't read the client's type tree — that means the client was patched
    and wiztype's memory signature is stale, which a re-dump cannot fix.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    logger.info(
        f"[entity_collision] pulling a fresh type dump for revision {revision} "
        f"from the running client via wiztype (one-time, ~10-30s)"
    )
    try:
        tree = wiztype.get_type_tree()
    except Exception as e:
        raise RuntimeError(
            f"wiztype could not read the client's type tree "
            f"({type(e).__name__}: {e}); the client was likely patched and wiztype's "
            f"memory signature is stale — upgrade wiztype "
            f"(`uv lock --upgrade-package wiztype && uv sync`)"
        ) from e
    tmp = path.with_suffix(".tmp")
    wiztype.JsonTypeDumperV1(tree).dump(tmp, indent=None)
    tmp.replace(path)
    logger.info(
        f"[entity_collision] type list cached at {path} "
        f"({path.stat().st_size // (1024 * 1024)} MB)"
    )


def _ensure_type_list(revision: str, *, force: bool = False) -> Path:
    """Return a usable cached TypeList for ``revision``.

    Re-pulls from the client when the cache is missing, unreadable, or ``force``d
    (e.g. the cached dump loaded fine but turned out to be incompatible with the
    running client). A client patch normally bumps ``revision`` — a new cache key —
    so the dump auto-refreshes; this also self-heals a corrupt same-revision cache.
    """
    path = _typelist_cache_path(revision)
    if not force and _typelist_is_loadable(path):
        return path
    _dump_type_list(revision, path)
    return path


def _extract_nif_asset(template) -> str | None:
    """Find the first `.nif` m_assetName in a deserialized template's behaviors."""
    try:
        behaviors = template["m_behaviors"]
    except Exception:
        return None
    if not isinstance(behaviors, LazyList):
        return None
    for behavior in behaviors:
        if not isinstance(behavior, LazyObject):
            continue
        try:
            asset = behavior["m_assetName"]
        except Exception:
            continue
        if isinstance(asset, (bytes, bytearray)):
            asset = asset.decode("latin-1", "replace")
        if isinstance(asset, str) and asset.lower().endswith(".nif"):
            return asset
    return None


def _has_solid_collision(template) -> bool:
    """Whether a template is a solid obstacle the player can't walk through."""
    try:
        behaviors = template["m_behaviors"]
    except Exception:
        return False
    if not isinstance(behaviors, LazyList):
        return False
    for behavior in behaviors:
        if not isinstance(behavior, LazyObject):
            continue
        try:
            solid = behavior["m_solidCollisionFilename"]
        except Exception:
            continue
        if isinstance(solid, (bytes, bytearray)):
            solid = solid.decode("latin-1", "replace")
        if solid:  # non-empty -> has solid collision geometry
            try:
                disabled = bool(behavior["m_bDisableCollision"])
            except Exception:
                disabled = False
            if not disabled:
                return True
    return False


class _Resolver:
    """Process-wide, lazily-initialized model-footprint resolver."""

    def __init__(self):
        # Reentrant: zone_static_objects() holds the lock while calling footprint_points().
        self._lock = threading.RLock()
        self._state = None  # None=untried, True=ready, False=unavailable
        self._serializer = None  # STATEFUL: ObjectData templates + spawnData
        self._world_serializer = None  # plain flags: gamedata.bin + TemplateManifest
        self._root = None
        self._gamedata = None
        self._template_paths: dict[str, str] = {}  # entity name -> ObjectData path
        self._asset_cache: dict[str, str | None] = {}  # entity name -> nif asset
        self._collidable_cache: dict[str, bool] = {}  # entity name -> is solid obstacle
        self._hull_cache: dict[str, list | None] = {}  # asset -> local hull points
        self._wads: dict[str, object] = {}
        self._id2name: dict[int, str] | None = None  # templateID -> template basename
        self._zone_static_cache: dict[str, list] = {}  # zone -> [(z, footprint), ...]
        # Model footprints are deterministic per NIF and only change on a game update,
        # so the asset/hull caches persist to disk (keyed by revision) — parsing the
        # NIFs is the warm-up cost, and this makes it a one-time-ever cost.
        self._cache_file: Path | None = None
        self._cache_dirty = False
        self._lang_cache: dict[
            tuple[str, str], dict[str, str]
        ] = {}  # (locale, file) -> table
        self._zone_name_cache: dict[
            tuple[str, str], str
        ] = {}  # (zone, locale) -> display

    def _initialize(self) -> bool:
        if self._state is not None:
            return self._state
        # Serialize first-time init across threads: generating the type list (wiztype)
        # is expensive and writes a file, so two callers must not race into it.
        with self._lock:
            if self._state is not None:
                return self._state
            self._state = self._do_initialize()
        return self._state

    def _do_initialize(self) -> bool:
        try:
            if not _PRECISE_AVAILABLE:
                raise RuntimeError("katsuba/kinif/wiztype not available")
            install = Path(get_wiz_install())
            self._gamedata = install / "Data" / "GameData"
            revision = (install / "Bin" / "revision.dat").read_text().strip()

            # The type list is generated on demand by wiztype and cached per revision,
            # so it's no longer shipped with Deimos. Build the resolver from it; if the
            # cached dump loads but turns out to be incompatible with the running client,
            # pull a fresh dump and rebuild once.
            for force in (False, True):
                types_path = _ensure_type_list(revision, force=force)
                self._setup_serializers(types_path)
                if self._probe_serializer():
                    break
                if force:
                    raise RuntimeError(
                        "type list still incompatible with the client after a fresh dump"
                    )
                logger.warning(
                    "[entity_collision] cached type list is incompatible with the "
                    "running client; pulling a fresh dump"
                )

            self._cache_file = _footprint_cache_path(revision)
            self._load_footprint_cache()

            logger.info(
                f"[entity_collision] precise resolver ready (revision {revision}, "
                f"{len(self._template_paths)} templates, "
                f"{len(self._hull_cache)} cached hulls)"
            )
            return True
        except Exception as e:
            logger.warning(
                f"[entity_collision] precise resolver unavailable ({e}); "
                f"entities will use bounding boxes"
            )
            return False

    def _setup_serializers(self, types_path: Path) -> None:
        """(Re)build the serializers, Root archive, and template index from a type list."""
        type_list = TypeList.open(str(types_path))
        opts = SerializerOptions()
        opts.flags |= STATEFUL_FLAGS
        opts.shallow = False
        opts.skip_unknown_types = True
        self._serializer = Serializer(opts, type_list)

        # gamedata.bin and TemplateManifest.xml are serialized without the stateful
        # property-hash flags the templates use; they need their own serializer.
        wopts = SerializerOptions()
        wopts.shallow = False
        wopts.skip_unknown_types = True
        self._world_serializer = Serializer(wopts, type_list)

        self._root = Archive.mmap(str(self._gamedata / "Root.wad"))
        self._template_paths.clear()
        for fp in self._root.iter_glob("ObjectData/**/*.xml"):
            self._template_paths[fp.rsplit("/", 1)[-1][:-4]] = fp
        self._id2name = None  # manifest must be re-read against the new serializer

    def _probe_serializer(self) -> bool:
        """Cheaply confirm the type list matches the client by deserializing a single
        template with the stateful serializer the resolver actually uses. A dump that
        opened fine but doesn't match the client throws or yields None here."""
        try:
            path = next(iter(self._template_paths.values()))
        except StopIteration:
            return False
        try:
            return self._root.deserialize(path, self._serializer) is not None
        except Exception:
            return False

    def _load_footprint_cache(self) -> None:
        """Seed the asset/hull caches from the on-disk footprint cache (best-effort)."""
        try:
            if self._cache_file and self._cache_file.exists():
                data = json.loads(self._cache_file.read_text(encoding="utf-8"))
                self._asset_cache.update(data.get("assets", {}))
                self._collidable_cache.update(data.get("collidable", {}))
                for asset, hull in data.get("hulls", {}).items():
                    self._hull_cache[asset] = [tuple(p) for p in hull] if hull else None
        except Exception as e:
            logger.warning(f"[entity_collision] footprint cache load failed ({e})")

    def _save_footprint_cache(self) -> None:
        """Persist the asset/hull caches to disk if they grew (atomic, best-effort)."""
        if not self._cache_dirty or not self._cache_file:
            return
        try:
            self._cache_file.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "assets": self._asset_cache,
                "collidable": self._collidable_cache,
                "hulls": self._hull_cache,
            }
            tmp = self._cache_file.with_suffix(".tmp")
            tmp.write_text(json.dumps(payload), encoding="utf-8")
            tmp.replace(self._cache_file)
            self._cache_dirty = False
        except Exception as e:
            logger.warning(f"[entity_collision] footprint cache save failed ({e})")

    def _open_wad(self, name: str):
        archive = self._wads.get(name)
        if archive is None:
            path = self._gamedata / name
            if not path.exists():
                return None
            archive = Archive.mmap(str(path))
            self._wads[name] = archive
        return archive

    def _read_nif(self, asset: str, zone_name: str | None) -> bytes | None:
        """Resolve a KI asset path to NIF bytes from the appropriate WAD."""
        if asset.startswith("|"):
            parts = asset.strip("|").split("|", 2)
            if len(parts) != 3:
                return None
            source, category, internal = parts
            candidates = [f"{source}-{category}.wad"]
        else:
            internal = asset
            zone_wad = zone_name.replace("/", "-") + ".wad" if zone_name else None
            # Many placed-object models (teleporters, StateObjects) live in the
            # world-level WorldData wad, e.g. "Azteca/AZ_Z00_Zocalo" -> Azteca-WorldData.wad.
            world_wad = (
                (zone_name.split("/")[0] + "-WorldData.wad")
                if zone_name and "/" in zone_name
                else None
            )
            candidates = (
                ([zone_wad] if zone_wad else [])
                + ([world_wad] if world_wad else [])
                + _FALLBACK_WADS
            )

        basename = internal.rsplit("/", 1)[-1]
        for wad_name in candidates:
            archive = self._open_wad(wad_name)
            if archive is None:
                continue
            try:
                return bytes(archive[internal])
            except Exception:
                for fp in archive.iter_glob(f"**/{basename}"):
                    try:
                        return bytes(archive[fp])
                    except Exception:
                        continue
        return None

    def _resolve_template(self, name: str) -> None:
        """Deserialize a template once, caching both its NIF asset and collidability."""
        if name in self._asset_cache and name in self._collidable_cache:
            return
        asset = None
        collidable = False
        path = self._template_paths.get(name)
        if path:
            try:
                template = self._root.deserialize(path, self._serializer)
                asset = _extract_nif_asset(template)
                collidable = _has_solid_collision(template)
            except Exception:
                pass
        self._asset_cache[name] = asset
        self._collidable_cache[name] = collidable
        self._cache_dirty = True

    def _asset_for(self, name: str) -> str | None:
        if name not in self._asset_cache:
            self._resolve_template(name)
        return self._asset_cache[name]

    def is_collidable(self, name: str) -> bool:
        """Whether a placed object named ``name`` is a solid obstacle. Thread-only."""
        if name not in self._collidable_cache:
            self._resolve_template(name)
        return self._collidable_cache[name]

    def _hull_for(self, asset: str, zone_name: str | None) -> list | None:
        if asset not in self._hull_cache:
            hull = None
            data = self._read_nif(asset, zone_name)
            if data:
                try:
                    verts = kinif.geometry_vertices(data)
                except Exception:
                    verts = None
                if verts:
                    poly = MultiPoint([(v[0], v[1]) for v in verts]).convex_hull
                    if poly.geom_type == "Polygon" and not poly.is_empty:
                        hull = list(poly.exterior.coords)
            self._hull_cache[asset] = hull
            self._cache_dirty = True
        return self._hull_cache[asset]

    def footprint_points(self, name: str, zone_name: str | None) -> list | None:
        """Local-space 2D hull points for an entity's model, or None. Thread-only."""
        if not self._initialize():
            return None
        with self._lock:
            asset = self._asset_for(name)
            if not asset:
                return None
            return self._hull_for(asset, zone_name)

    def _load_manifest(self) -> None:
        """Build the templateID -> template basename map from Root.wad's manifest (once)."""
        if self._id2name is not None:
            return
        id2name: dict[int, str] = {}
        try:
            manifest = self._root.deserialize(
                "TemplateManifest.xml", self._world_serializer
            )
            for entry in manifest["m_serializedTemplates"]:
                if entry is None:
                    continue
                tid = entry["m_id"]
                fn = entry["m_filename"]
                if isinstance(fn, (bytes, bytearray)):
                    fn = fn.decode("latin-1", "replace")
                base = fn.rsplit("/", 1)[-1]
                if base.endswith(".xml"):
                    base = base[:-4]
                id2name[tid] = base
        except Exception as e:
            logger.warning(
                f"[entity_collision] could not load TemplateManifest ({e}); "
                f"static objects will use bounding boxes"
            )
        self._id2name = id2name

    def zone_static_objects(self, zone_name: str) -> list:
        """All static placed-object footprints in a zone, as ``[(z, polygon), ...]``.

        Reads the zone's ``gamedata.bin`` object table (whole zone, from files — no
        render dependency), resolves each object's model footprint and places it at the
        object's world transform. Cached per zone. Thread-only.
        """
        if not self._initialize():
            return []
        with self._lock:
            cached = self._zone_static_cache.get(zone_name)
            if cached is not None:
                return cached

            placed: list = []
            precise = 0
            try:
                self._load_manifest()
                archive = self._open_wad(zone_name.replace("/", "-") + ".wad")
                if archive is None:
                    self._zone_static_cache[zone_name] = placed
                    return placed

                zone_data = archive.deserialize("gamedata.bin", self._world_serializer)
                for inst in zone_data["m_objectList"]:
                    if inst is None:  # a CoreObjectInfo subtype not in the TypeList
                        continue
                    try:
                        tid = inst["m_templateID.m_full"]
                        loc = inst["m_location"]
                        ori = inst["m_orientation"]
                        obj_scale = inst["m_fScale"] or 1.0
                    except Exception:
                        continue

                    name = self._id2name.get(tid) if self._id2name else None
                    # Only solid obstacles block the player. Skip everything else —
                    # decorative meshes (archways), walk-on triggers, NPCs (soft capsule),
                    # and templates we can't resolve — so we don't shove teleports around
                    # things you can actually walk through.
                    if not name or not self.is_collidable(name):
                        continue

                    shape = None
                    points = self.footprint_points(name, zone_name)
                    if points:
                        poly = Polygon(points)
                        if poly.is_valid and not poly.is_empty:
                            # model-local hull -> scale -> rotate by yaw -> world position
                            poly = scale(
                                poly, xfact=obj_scale, yfact=obj_scale, origin=(0, 0)
                            )
                            poly = rotate(poly, ori.z, origin=(0, 0), use_radians=True)
                            shape = translate(poly, xoff=loc.x, yoff=loc.y)
                            precise += 1
                    if shape is None:
                        # collidable, but the model is a placeholder/unparsable NIF
                        shape = Point(loc.x, loc.y).buffer(
                            _DEFAULT_STATIC_RADIUS * obj_scale
                        )

                    if shape is not None and not shape.is_empty:
                        placed.append((loc.z, shape))

                logger.debug(
                    f"[entity_collision] {zone_name}: {len(placed)} static object footprints "
                    f"({precise} precise model, {len(placed) - precise} bounding box)"
                )
            except Exception as e:
                logger.warning(
                    f"[entity_collision] static objects unavailable for {zone_name} ({e})"
                )

            self._save_footprint_cache()  # persist any newly-parsed model footprints
            self._zone_static_cache[zone_name] = placed
            return placed

    def _lang_table(self, langfile: str, locale: str) -> dict[str, str]:
        """Parse and cache a W101 ``.lang`` file from Root.wad.

        Format (UTF-16-LE): a ``1:<File>`` header, then entries of
        ``<key>\\r\\n\\r\\n<value>`` back-to-back — so after the header it's
        ``[key, "", value]`` repeating.
        """
        ck = (locale, langfile)
        table = self._lang_cache.get(ck)
        if table is None:
            table = {}
            try:
                raw = bytes(self._root[f"Locale/{locale}/{langfile}.lang"]).decode(
                    "utf-16-le"
                )
                lines = raw.split("\r\n")
                i = 1  # skip the "1:<File>" header
                while i + 2 < len(lines):
                    key = lines[i].strip()
                    if key:
                        table[key] = lines[i + 2]
                    i += 3
            except Exception:
                pass  # missing/locale-less lang file -> empty table, resolves to None
            self._lang_cache[ck] = table
        return table

    def _resolve_lang(self, token: str, locale: str) -> str | None:
        """Resolve a ``<LangFile>_<key>`` token (e.g. ``WizardZone_00000987``)."""
        if not token or "_" not in token:
            return None
        langfile, key = token.split("_", 1)
        return self._lang_table(langfile, locale).get(key)

    def _resolve_one_zone(self, path: str, locale: str) -> str | None:
        """Display name for exactly this zone path (no parent fallback), or None."""
        try:
            archive = self._open_wad(path.replace("/", "-") + ".wad")
            if archive is None:
                return None
            zone_data = archive.deserialize("gamedata.bin", self._world_serializer)
            token = zone_data["m_zoneDisplayName"]
            if isinstance(token, (bytes, bytearray)):
                token = token.decode("latin-1", "replace")
            return self._resolve_lang(token, locale)
        except Exception as e:
            logger.debug(f"[entity_collision] no display name for {path} ({e})")
            return None

    def zone_display_name(self, zone_name: str, locale: str = "en-US") -> str | None:
        """Canonical display name for a zone path, or None. Thread-safe, cached.

        ``Azteca/AZ_Z00_Zocalo`` -> ``The Zocalo`` via the zone's gamedata.bin
        ``m_zoneDisplayName`` lang token resolved against the Root.wad lang files.

        Zone paths are hierarchical, so if the full path has no display name (e.g. a
        sub-area that ships no gamedata of its own) we walk up to the parent zone; we're
        still physically inside it, so its name is the accurate answer:
        ``Azteca/AZ_Z00_Zocalo/SomeSubArea`` -> ``The Zocalo``.
        """
        if not self._initialize():
            return None
        with self._lock:
            return self._zone_display_walk(zone_name, locale)

    def _zone_display_walk(self, path: str, locale: str) -> str | None:
        ck = (path, locale)
        if ck in self._zone_name_cache:
            return self._zone_name_cache[ck] or None
        name = self._resolve_one_zone(path, locale)
        if not name and "/" in path:
            name = self._zone_display_walk(
                path.rsplit("/", 1)[0], locale
            )  # parent zone
        self._zone_name_cache[ck] = name or ""
        return name

    def world_display_name(
        self, world_segment: str, locale: str = "en-US"
    ) -> str | None:
        """Canonical world name for a path's first segment via WorldNames.lang.

        ``WizardCity`` -> ``Wizard City``, ``DragonSpire`` -> ``Dragonspyre``. Returns
        None for segments not in the table (event/PvP namespaces); the caller decides
        the fallback. Thread-safe, cached (the lang table is parsed once).
        """
        if not self._initialize():
            return None
        with self._lock:
            return self._lang_table("WorldNames", locale).get(world_segment)


_resolver = _Resolver()


def build_zone_static_shapes(
    zone_name: str | None, target_z: float | None = None, z_threshold: float = 700.0
) -> list[Polygon]:
    """In a worker thread: the zone's static-object collision footprints.

    Reads every placed object from the zone's ``gamedata.bin`` (whole zone, from files,
    so colliders outside render range are known before teleporting), resolving each to
    a precise model footprint or a bounding circle. When ``target_z`` is given, objects
    clearly on another floor (``|z - target_z|`` beyond the threshold) are dropped so
    geometry above/below the player doesn't block the solve. Results are cached per zone.
    """
    if not zone_name:
        return []
    placed = _resolver.zone_static_objects(zone_name)
    if target_z is None:
        return [shape for _z, shape in placed]
    return [shape for z, shape in placed if abs(z - target_z) <= z_threshold]


def get_zone_display_name(zone_name: str, locale: str = "en-US") -> str | None:
    """Canonical, human-readable name for a zone path (any zone, not just the current one).

    Reads the zone's ``gamedata.bin`` display token and resolves it against the game's
    lang files, e.g. ``Azteca/AZ_Z00_Zocalo`` -> ``The Zocalo``. Returns None if it can't
    be resolved (no TypeList, zone wad missing, locale without that lang file). Cached.
    """
    if not zone_name:
        return None
    return _resolver.zone_display_name(zone_name, locale)


def get_world_display_name(world_segment: str, locale: str = "en-US") -> str | None:
    """Canonical name for a world (a zone path's first segment), e.g. ``WizardCity`` ->
    ``Wizard City``, ``DragonSpire`` -> ``Dragonspyre``.

    Resolves via the game's ``WorldNames.lang``; for segments not in that table (event,
    PvP, test namespaces) it falls back to splitting CamelCase into words so the result
    is still presentable. Cached.
    """
    if not world_segment:
        return world_segment
    name = _resolver.world_display_name(world_segment, locale)
    if name:
        return name
    return " ".join(re.findall("[A-Z][^A-Z]*", world_segment)) or world_segment
