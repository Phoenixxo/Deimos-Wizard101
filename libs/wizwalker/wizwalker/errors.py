import asyncio
from typing import Awaitable, TypeVar, Union


_T = TypeVar("_T")


def preserve_cleanup_errors(
    primary_error: BaseException,
    cleanup_errors,
    *,
    operation: str,
) -> BaseException:
    """Attach rollback failures without replacing the operation's real failure.

    Lifecycle callers deliberately re-raise ``primary_error`` after calling this
    helper.  Keeping the original exception object preserves its concrete type,
    traceback, native diagnostic fields, and cancellation semantics while making
    every cleanup failure available to structured logging and exception notes.

    Repeated cleanup attempts may report the same exception object, so identity
    de-duplication prevents diagnostics from growing on retries.
    """
    existing = tuple(getattr(primary_error, "cleanup_errors", ()))
    retained = list(existing)
    for cleanup_error in cleanup_errors:
        if not isinstance(cleanup_error, BaseException):
            cleanup_error = RuntimeError(str(cleanup_error))
        if cleanup_error is primary_error:
            continue
        if any(cleanup_error is retained_error for retained_error in retained):
            continue
        retained.append(cleanup_error)

    added = retained[len(existing):]
    if not added:
        return primary_error

    primary_error.cleanup_errors = tuple(retained)
    add_note = getattr(primary_error, "add_note", None)
    if callable(add_note):
        descriptions = "; ".join(
            f"{type(error).__name__}: {error}" for error in added
        )
        add_note(
            f"{operation} also failed during rollback/cleanup: {descriptions}"
        )
    return primary_error


def propagate_cleanup_control_flow(
    primary_error: BaseException,
    cleanup_error: BaseException,
    *,
    operation: str,
) -> None:
    """Never turn cancellation or another control-flow signal into an Exception.

    If ordinary activation failed just before rollback was interrupted by a
    ``BaseException`` such as ``CancelledError``, the interrupt must remain the
    raised value.  The activation failure is kept as its explicit cause and as
    structured diagnostic metadata.
    """
    if not isinstance(primary_error, Exception) or isinstance(
        cleanup_error, Exception
    ):
        return
    cleanup_error.interrupted_error = primary_error
    add_note = getattr(cleanup_error, "add_note", None)
    if callable(add_note):
        add_note(
            f"{operation} was interrupted while handling "
            f"{type(primary_error).__name__}: {primary_error}"
        )
    raise cleanup_error from primary_error


async def await_critical_operation(
    awaitable: Awaitable[_T],
    *,
    operation: str,
) -> _T:
    """Let an admitted operation settle before delivering task cancellation.

    Executor work and native RPCs cannot actually be cancelled once dispatched.
    Letting the asyncio wrapper disappear early creates an ordering hole where a
    rollback can run before the operation that installed the resource finishes.
    Shielding alone is insufficient because a second ``Task.cancel()`` can still
    interrupt the caller's next await.  This loop drains the admitted operation,
    remembers the first exact ``CancelledError`` object, and re-raises that same
    object after the operation is known to have settled.

    The caller's cancellation count is intentionally left untouched.  We never
    call ``Task.uncancel()``; cancellation remains observable to task groups and
    other structured-concurrency owners.
    """
    result, cancellation = await settle_critical_operation(
        awaitable,
        operation=operation,
    )
    if cancellation is not None:
        cancellation.settled_result = result
        raise cancellation
    return result


async def settle_critical_operation(
    awaitable: Awaitable[_T],
    *,
    operation: str,
) -> tuple[_T, asyncio.CancelledError | None]:
    """Return an admitted result plus any cancellation deferred while it ran."""
    task = asyncio.ensure_future(awaitable)
    owner = asyncio.current_task()
    owner_cancellation_count = owner.cancelling() if owner is not None else 0
    cancellation: asyncio.CancelledError | None = None
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError as error:
            owner_cancelled = (
                owner is not None
                and owner.cancelling() > owner_cancellation_count
            )
            if task.done():
                if task.cancelled() and not owner_cancelled and cancellation is None:
                    # The admitted operation cancelled itself.  It is the
                    # operation result, not an external interruption to defer.
                    raise
                if cancellation is None:
                    cancellation = error
                break
            if cancellation is None:
                cancellation = error
        except BaseException:
            if not task.done():
                raise
            break

    try:
        result = task.result()
    except BaseException as operation_error:
        if cancellation is None:
            raise
        preserve_cleanup_errors(
            cancellation,
            (operation_error,),
            operation=f"{operation} completion after cancellation",
        )
        raise cancellation from operation_error

    return result, cancellation


async def await_cleanup_preserving_cancellation(
    awaitable: Awaitable[_T],
    primary_error: BaseException,
    *,
    operation: str,
) -> tuple[_T | None, BaseException | None]:
    """Drain rollback despite repeated cancellation and retain all diagnostics.

    Returns ``(result, cleanup_error)`` for ordinary cleanup outcomes.  Callers
    keep retry ownership published when ``cleanup_error`` is non-None.  If an
    ordinary primary failure is interrupted by cancellation while cleanup is in
    progress, the first cancellation remains dominant after cleanup settles, as
    required by ``propagate_cleanup_control_flow``.  When cancellation was
    already the primary failure, later cancellation requests do not replace its
    exception identity.
    """
    task = asyncio.ensure_future(awaitable)
    owner = asyncio.current_task()
    owner_cancellation_count = owner.cancelling() if owner is not None else 0
    cleanup_interruption: asyncio.CancelledError | None = None
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError as error:
            owner_cancelled = (
                owner is not None
                and owner.cancelling() > owner_cancellation_count
            )
            if (
                owner_cancelled
                and not isinstance(primary_error, asyncio.CancelledError)
                and cleanup_interruption is None
            ):
                cleanup_interruption = error
            if task.done():
                break
        except BaseException:
            if not task.done():
                raise
            break

    result: _T | None = None
    cleanup_error: BaseException | None = None
    try:
        result = task.result()
    except BaseException as error:
        cleanup_error = error

    if cleanup_interruption is not None:
        if cleanup_error is not None:
            preserve_cleanup_errors(
                cleanup_interruption,
                (cleanup_error,),
                operation=operation,
            )
        propagate_cleanup_control_flow(
            primary_error,
            cleanup_interruption,
            operation=operation,
        )

    if cleanup_error is not None:
        propagate_cleanup_control_flow(
            primary_error,
            cleanup_error,
            operation=operation,
        )
        preserve_cleanup_errors(
            primary_error,
            (
                cleanup_error,
                *tuple(getattr(cleanup_error, "cleanup_errors", ())),
            ),
            operation=operation,
        )
    return result, cleanup_error


class WizWalkerError(Exception):
    """
    Base wizwalker exception, all exceptions raised should inherit from this
    """


class ExceptionalTimeout(WizWalkerError):
    def __init__(self, msg, possible_exception: Exception = None):
        super().__init__(msg)
        self.possible_exception = possible_exception


class ClientClosedError(WizWalkerError):
    """
    Raised when trying to do an action that requires a running client
    """

    def __init__(self):
        super().__init__("Client must be running to preform this action.")


class UnsupportedClientOperation(WizWalkerError):
    """Raised when native discovery does not support a legacy window action."""

    def __init__(self, operation: str):
        self.operation = operation
        super().__init__(
            f"Native client discovery does not support {operation} yet. "
            "Use the legacy Windows client until native window and input support is available."
        )


class HookNotActive(WizWalkerError):
    """
    Raised when doing something that requires a hook to be active,
    but it is not

    Attributes:
        hook_name: Name of the hook that is not active
    """

    def __init__(self, hook_name: str):
        super().__init__(f"{hook_name} is not active.")
        self.hook_name = hook_name


class HookAlreadyActivated(WizWalkerError):
    """
    Raised when trying to activate an active hook

    Attributes:
        hook_name: Name of the hook that is already active
    """

    def __init__(self, hook_name: str):
        super().__init__(f"{hook_name} was already activated.")
        self.hook_name = hook_name


class HookHeartbeatFailure(WizWalkerError):
    """One native hook lease generation failed its health contract."""

    code = "hook_heartbeat_failed"
    operation = "memory.hook.heartbeat"

    def __init__(
        self,
        scope: str,
        cause: BaseException,
        *,
        expected_hooks: set[str] | frozenset[str] = frozenset(),
    ):
        self.scope = scope
        self.cause = cause
        self.expected_hooks = frozenset(expected_hooks)
        self.details = {
            "scope": scope,
            "expected_hooks": sorted(self.expected_hooks),
            "cause_type": type(cause).__name__,
            "cause_code": getattr(cause, "code", None),
            "cause_operation": getattr(cause, "operation", None),
        }
        super().__init__(f"{scope} hook heartbeat failed: {cause}")


class WizWalkerMemoryError(WizWalkerError):
    """
    Raised to error with reading/writing memory
    """


class PatternMultipleResults(WizWalkerMemoryError):
    """
    Raised when a pattern has more than one result
    """


class PatternFailed(WizWalkerMemoryError):
    """
    Raised when the pattern scan fails
    """

    def __init__(self, pattern):
        super().__init__(
            f"Pattern {pattern} failed. You most likely need to restart the client."
        )


class MemoryInvalidated(WizWalkerMemoryError):
    """
    Raised when trying to read memory that has deallocated
    """


class MemoryReadError(WizWalkerMemoryError):
    """
    Raised when we couldn't read some memory
    """

    def __init__(self, address_or_message: Union[int, str]):
        if isinstance(address_or_message, int):
            super().__init__(f"Unable to read memory at address {address_or_message}.")
        else:
            super().__init__(address_or_message)


class AddressOutOfRange(MemoryReadError):
    def __init__(self, address):
        super().__init__(f"Address {address} out of bounds")


class MemoryWriteError(WizWalkerMemoryError):
    """
    Raised when we couldn't write to some memory
    """

    def __init__(self, address: int):
        super().__init__(f"Unable to write memory at address {address}.")


class UnsupportedMemoryOperation(WizWalkerMemoryError):
    """Raised when a selected memory backend does not support a mutation."""

    def __init__(self, operation: str):
        self.operation = operation
        super().__init__(
            f"The selected memory backend does not support {operation}. "
            "Use the Pymem backend until Rust mutation support is available."
        )


class ReadingEnumFailed(WizWalkerMemoryError):
    """
    Raised when the value passed to an enum is not valid
    """

    def __init__(self, enum, value):
        super().__init__(f"Error reading enum: {value} is not a vaid {enum}.")


class HookNotReady(WizWalkerMemoryError):
    """
    Raised when trying to use a value from a hook before hook has run

    Attributes:
        hook_name: Name of the hook that is not ready
    """

    def __init__(self, hook_name: str):
        super().__init__(f"{hook_name} has not run yet and is not ready.")


class WizWalkerCombatError(WizWalkerError):
    """
    Raised for errors relating to combat
    """


class NotInCombat(WizWalkerCombatError):
    """
    Raised when trying to do an action that requires the client
    to be in combat
    """


class NotEnoughPips(WizWalkerCombatError):
    """
    Raised when trying to use a card that costs more pips then
    are available
    """


class NotEnoughMana(WizWalkerCombatError):
    """
    Raised when trying to use a card that cost more mana than
    is available
    """


class CardAlreadyEnchanted(WizWalkerError):
    """
    Raised when trying to enchant an already enchanted card
    """

    def __init__(self):
        super().__init__("That card is already enchanted.")


# TODO: remove in 2.0
class HotkeyRegistrationError(WizWalkerError):
    """A global shortcut could not be registered or removed."""

    def __init__(
        self,
        message: str,
        *,
        code: str,
        keycode: int | None = None,
        modifiers: int | None = None,
        details=None,
        technical_message: str | None = None,
        operation: str | None = None,
    ):
        super().__init__(message)
        self.code = code
        self.operation = operation or (
            "hotkey.unregister"
            if code == "hotkey_not_registered"
            else "hotkey.register"
        )
        self.keycode = keycode
        self.modifiers = modifiers
        self.details = details or {}
        self.technical_message = technical_message


class HotkeyAlreadyRegistered(HotkeyRegistrationError):
    def __init__(
        self,
        keycode,
        modifiers=0,
        *,
        message=None,
        details=None,
        technical_message=None,
    ):
        raw_keycode = getattr(keycode, "value", keycode)
        try:
            numeric_keycode = int(raw_keycode)
        except (TypeError, ValueError):
            numeric_keycode = None
        if message is None:
            if numeric_keycode is None:
                message = f"{keycode} already registered"
            else:
                message = (
                    f"The shortcut using key {numeric_keycode} and modifiers "
                    f"{int(modifiers)} is already registered."
                )
        super().__init__(
            message,
            code="hotkey_conflict",
            keycode=numeric_keycode,
            modifiers=int(modifiers),
            details=details,
            technical_message=technical_message,
        )


class HotkeyBackendUnavailable(HotkeyRegistrationError):
    def __init__(self, message: str):
        super().__init__(message, code="hotkey_backend_unavailable")
