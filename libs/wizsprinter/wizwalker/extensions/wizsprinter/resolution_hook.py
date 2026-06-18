"""In-process resolution forcing via WizWalker-style asm hooks.

Cross-process tools can resize the window and write the camera frustum, but they
CANNOT force the D3D backbuffer to a chosen size (that requires intercepting the
game's mode-set call and rewriting its width/height registers). This module does
that from inside the game process using WizWalker's hook framework, so Deimos can
force an arbitrary, crisp render resolution.

Two pattern-scanned asm hooks (build/ASLR-resilient):

* SetModeResHook — the engine's "set video mode" function:
      setMode(this /*rcx*/, width /*edx*/, height /*r8d*/, flags /*r9d*/, hwnd)
  When our control block's `enabled` flag is set, we overwrite edx/r8d with the
  forced width/height, so the device is (re)created at exactly that size.

* VideoManagerHook — the per-frame "process pending video-mode change" function.
  Its `this` (rcx) is the video manager, whose byte at +0x2229b is a pending-change
  flag the engine polls each frame. We capture that `this` pointer to an export so
  we can set the flag and trigger the apply on demand.

To force WxH: write {enabled, width, height} to the control block, then set the
manager's pending byte. The engine runs its own full apply on the game thread
(release -> setMode -> Reset); setMode's args come out as our WxH. Aspect (the 3D
projection) is corrected separately via the CamView frustum (see Deimos client
resizing) since it derives from the frustum, not the backbuffer.
"""
import struct

from wizwalker.memory.hooks import SimpleHook
from wizwalker.memory.memory_reader import Primitive

# Video-manager field offsets (this build of WizardGraphicalClient.exe).
MGR_PENDING_FLAG_OFF = 0x2229B  # byte: non-zero => apply pending video mode


class SetModeResHook(SimpleHook):
    """Override setMode's width (edx) / height (r8d) with a forced size."""

    # mov [rsp+8],rbx ; mov [rsp+20],r9d ; mov [rsp+18],r8d ; mov [rsp+10],edx ;
    # push rbp/rsi/rdi/r12/r13/r14/r15 ; sub rsp,0xB0
    pattern = (
        rb"\x48\x89\x5C\x24\x08\x44\x89\x4C\x24\x20\x44\x89\x44\x24\x18"
        rb"\x89\x54\x24\x10\x55\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57"
        rb"\x48\x81\xEC\xB0\x00\x00\x00"
    )
    instruction_length = 5  # mov qword [rsp+8], rbx
    # control block: u32 enabled, u32 width, u32 height
    exports = [("control_block", 12)]

    async def bytecode_generator(self, packed_exports):
        ctrl = packed_exports[0][1]  # packed 8-byte address of control_block
        return (
            b"\x48\xB8" + ctrl          # mov rax, control_block
            + b"\x83\x38\x00"           # cmp dword [rax], 0     (enabled?)
            + b"\x74\x07"               # je +7  -> skip the two movs
            + b"\x8B\x50\x04"           # mov edx, [rax+4]       (forced width)
            + b"\x44\x8B\x40\x08"       # mov r8d, [rax+8]       (forced height)
            # ---- original overwritten instruction ----
            + b"\x48\x89\x5C\x24\x08"   # mov [rsp+8], rbx
        )


class VideoManagerHook(SimpleHook):
    """Capture the video-manager `this` (rcx) at the per-frame mode checker."""

    # The short prologue is generic; extend the pattern to the distinctive
    # `cmp byte [rcx+0x2229b], 0` (the pending-mode-change poll) for uniqueness.
    # Prologue ... mov rbx,rcx ; cmp byte [rcx+0x2229b], 0
    pattern = (
        rb"\x48\x8B\xC4\x55\x57\x41\x56\x48\x8D\x68\xB8\x48\x81\xEC\x30\x01\x00\x00"
        rb"\x48\xC7\x44\x24\x70\xFE\xFF\xFF\xFF\x48\x89\x58\x10\x48\x89\x70\x18"
        rb"\x0F\x29\x70\xD8\x0F\x29\x78\xC8\x44\x0F\x29\x40\xB8\x48\x8B\xD9"
        rb"\x80\xB9\x9B\x22\x02\x00\x00"
    )
    instruction_length = 5  # mov rax,rsp ; push rbp ; push rdi
    exports = [("manager_ptr", 8)]

    async def bytecode_generator(self, packed_exports):
        mgr = packed_exports[0][1]  # packed 8-byte address of manager_ptr slot
        return (
            b"\x48\xB8" + mgr          # mov rax, manager_ptr  (our export slot)
            + b"\x48\x89\x08"          # mov [rax], rcx        (store the manager 'this')
            # ---- original overwritten instructions ----
            + b"\x48\x8B\xC4"          # mov rax, rsp
            + b"\x55"                  # push rbp
            + b"\x57"                  # push rdi
        )


class ResolutionForcer:
    """Installs the resolution asm hooks on a client and forces crisp resolutions.

    Usage::

        forcer = ResolutionForcer(client)
        await forcer.install()
        await forcer.force(1920, 1080)   # device re-created at 1920x1080
        ...
        await forcer.release()           # stop overriding (game keeps last size)
        await forcer.uninstall()         # remove hooks
    """

    def __init__(self, client):
        self.client = client
        self.hook_handler = client.hook_handler
        self._setmode = None
        self._vm = None

    @property
    def installed(self) -> bool:
        return self._setmode is not None

    async def install(self):
        if self.installed:
            return
        # Ensure the shared codecave region is prepared (idempotent).
        await self.hook_handler._check_for_autobot()
        # Track each hook the instant it installs so a failure mid-install still
        # gets cleaned up (a dangling jump to a freed codecave would crash the game).
        try:
            self._setmode = SetModeResHook(self.hook_handler)
            await self._setmode.hook()
            self._vm = VideoManagerHook(self.hook_handler)
            await self._vm.hook()
        except Exception:
            await self.uninstall()
            raise

    async def uninstall(self):
        for hook in (self._setmode, self._vm):
            if hook is not None:
                try:
                    await hook.unhook()
                except Exception:
                    pass
        self._setmode = None
        self._vm = None

    async def _manager_address(self) -> int:
        """The captured video-manager pointer (0 until the checker has run once)."""
        if self._vm is None:
            return 0
        try:
            return await self.hook_handler.read_typed(self._vm.manager_ptr, Primitive.int64)
        except Exception:
            return 0

    async def force(self, width: int, height: int) -> bool:
        """Force the render resolution to width x height (in-process, crisp).

        Arms the setMode override and triggers the engine's own apply. Returns
        True if the apply was triggered (manager captured), False otherwise.
        """
        if not self.installed:
            return False
        await self.hook_handler.write_bytes(
            self._setmode.control_block, struct.pack("<III", 1, int(width), int(height))
        )
        mgr = await self._manager_address()
        if not mgr:
            return False
        # Trigger the engine's per-frame apply.
        await self.hook_handler.write_bytes(mgr + MGR_PENDING_FLAG_OFF, b"\x01")
        return True

    async def release(self):
        """Stop overriding setMode (the device keeps whatever size it last got)."""
        if self._setmode is not None:
            try:
                await self.hook_handler.write_bytes(
                    self._setmode.control_block, struct.pack("<III", 0, 0, 0)
                )
            except Exception:
                pass


# --- WM_NCHITTEST border hook (makes the game window drag-resizable in-process) ---
# The game's WndProc returns HTCLIENT even on a WS_THICKFRAME border, so the window
# isn't grab-resizable from out-of-process. This hooks the WndProc and, for
# WM_NCHITTEST inside the client area near an edge, returns the matching resize
# hit-code (HTLEFT/HTRIGHT/.../corners). It reads the window's screen rect + grab
# margin from a control block the host updates each tick (so no GetWindowRect call
# in the codecave). Everything else passes through unchanged.

# Codecave assembly. CTRL -> {left,top,right,bottom,margin} as 5x int32.
_NCHIT_ASM = """
    push  rbx
    cmp   edx, 0x84
    jne   done_pop
    movsx eax, r9w
    mov   r10d, r9d
    sar   r10d, 16
    mov   r11, 0x{ctrl:x}
    mov   ebx, [r11]
    add   ebx, [r11+16]
    cmp   eax, ebx
    jl    on_left
    mov   ebx, [r11+8]
    sub   ebx, [r11+16]
    cmp   eax, ebx
    jge   on_right
    jmp   check_vert
on_left:
    mov   ebx, [r11+4]
    add   ebx, [r11+16]
    cmp   r10d, ebx
    jl    ret_13
    mov   ebx, [r11+12]
    sub   ebx, [r11+16]
    cmp   r10d, ebx
    jge   ret_16
    jmp   ret_10
on_right:
    mov   ebx, [r11+4]
    add   ebx, [r11+16]
    cmp   r10d, ebx
    jl    ret_14
    mov   ebx, [r11+12]
    sub   ebx, [r11+16]
    cmp   r10d, ebx
    jge   ret_17
    jmp   ret_11
check_vert:
    mov   ebx, [r11+4]
    add   ebx, [r11+16]
    cmp   r10d, ebx
    jl    ret_12
    mov   ebx, [r11+12]
    sub   ebx, [r11+16]
    cmp   r10d, ebx
    jge   ret_15
    jmp   done_pop
ret_10: mov eax, 10
        jmp do_ret
ret_11: mov eax, 11
        jmp do_ret
ret_12: mov eax, 12
        jmp do_ret
ret_13: mov eax, 13
        jmp do_ret
ret_14: mov eax, 14
        jmp do_ret
ret_15: mov eax, 15
        jmp do_ret
ret_16: mov eax, 16
        jmp do_ret
ret_17: mov eax, 17
do_ret: pop rbx
        ret
done_pop:
    pop   rbx
"""


def _assemble(asm: str) -> bytes:
    import keystone  # optional dep; only needed for the resize-border hook
    asm = "\n".join(line.split(";")[0] for line in asm.splitlines())  # strip ; comments
    ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
    return bytes(ks.asm(asm, 0)[0])


class WndProcNCHitHook(SimpleHook):
    """Return resize hit-codes near the window edges so the window is drag-resizable."""

    # sub rsp,0x38 ; mov r10,rcx ; mov rcx,[rip+disp(wildcard)] ; test rcx,rcx ; je ;
    # mov rax,[rcx] ; mov [rsp+20],r9 ; mov r9,rax
    # NB: the scanner treats the pattern as a regex, so bytes that are regex
    # metacharacters must be wildcarded with `.` (any byte) — here 0x24 ('$') in
    # `mov [rsp+0x20]`; the 4 dots wildcard the rip-relative displacement.
    pattern = (
        rb"\x48\x83\xEC\x38\x4C\x8B\xD1\x48\x8B\x0D...."
        rb"\x48\x85\xC9\x74\x1C\x48\x8B\x01\x4C\x89\x4C.\x20\x4D\x8B\xC8"
    )
    instruction_length = 7  # sub rsp,0x38 ; mov r10,rcx
    exports = [("hit_rect", 20)]  # int32 left, top, right, bottom, margin

    async def get_hook_address(self, size: int) -> int:
        # The default 50 bytes isn't enough for this codecave (~210 bytes).
        return await self.alloc(256)

    async def get_hook_bytecode(self) -> bytes:
        # Allocate the export (sets self.hit_rect), assemble using its address, then
        # append the original overwritten bytes; SimpleHook appends the jump back.
        addr = self.hook_handler.process.allocate(self.exports[0][1])
        self.hit_rect = addr
        body = _assemble(_NCHIT_ASM.format(ctrl=addr))
        original = await self.read_bytes(self.jump_address, self.instruction_length)
        bytecode = body + original

        return_addr = self.jump_address + self.instruction_length
        rel = return_addr - (self.hook_address + len(bytecode)) - 5
        bytecode += b"\xE9" + struct.pack("<i", rel)
        return bytecode

    async def prehook(self):
        # Initialise the rect to a no-edge sentinel before the jump goes live, so the
        # first messages never hit a stale/zeroed rect (which would resize-grab).
        await self.hook_handler.write_bytes(
            self.hit_rect, struct.pack("<iiiii", -2_000_000_000, -2_000_000_000,
                                       2_000_000_000, 2_000_000_000, 0)
        )

    async def unhook(self):
        await super().unhook()
        if getattr(self, "hit_rect", None):
            await self.free(self.hit_rect)


class WindowResizeBorder:
    """Installs the WndProc hit-test hook and keeps the window rect updated so the
    game window is drag-resizable. Call update_rect(screen_rect, margin) each tick."""

    def __init__(self, client):
        self.client = client
        self.hook_handler = client.hook_handler
        self._hook = None

    @property
    def installed(self) -> bool:
        return self._hook is not None

    async def install(self):
        if self.installed:
            return
        await self.hook_handler._check_for_autobot()
        self._hook = WndProcNCHitHook(self.hook_handler)
        await self._hook.hook()

    async def uninstall(self):
        if self._hook is not None:
            try:
                await self._hook.unhook()
            except Exception:
                pass
            self._hook = None

    async def update_rect(self, left: int, top: int, right: int, bottom: int, margin: int = 14):
        if self._hook is None:
            return
        await self.hook_handler.write_bytes(
            self._hook.hit_rect, struct.pack("<iiiii", left, top, right, bottom, margin)
        )
