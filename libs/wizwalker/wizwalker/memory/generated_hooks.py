from hashlib import file_digest

from wizwalker.errors import MemoryReadError

from .generated import wiz_hooks


class GeneratedHookResolver:
    """Check the game build and live bytes before using a generated address."""

    def __init__(self):
        self._matches_build = None

    async def resolve(self, reader, name: str, *, original: bytes | None = None) -> int | None:
        definition = wiz_hooks.HOOKS.get(name)
        if (
            definition is None
            or not isinstance(definition.target, wiz_hooks.Rva)
            or definition.target.module != "WizardGraphicalClient.exe"
        ):
            return None
        if not definition.evidence:
            return None

        target = definition.target
        if original is None:
            if definition.overwrite_size != 0:
                return None
        elif len(original) > definition.overwrite_size or not any(
            proof.address.module == target.module
            and (offset := target.rva - proof.address.rva) >= 0
            and proof.data[offset : offset + len(original)] == original
            for proof in definition.evidence
        ):
            return None

        module = await reader.loaded_module(target.module)
        if module is None:
            return None
        if self._matches_build is None:
            self._matches_build = await reader.run_in_executor(
                self._has_matching_hash, module.filename
            )
        if not self._matches_build:
            return None

        base = module.lpBaseOfDll
        try:
            for proof in definition.evidence:
                if proof.address.module != target.module:
                    return None
                if await reader.read_bytes(base + proof.address.rva, len(proof.data)) != proof.data:
                    return None
        except MemoryReadError:
            return None
        return base + target.rva

    @staticmethod
    def _has_matching_hash(path: str) -> bool:
        try:
            with open(path, "rb") as executable:
                return file_digest(executable, "sha256").hexdigest() == wiz_hooks.GAME_SHA256
        except OSError:
            return False
