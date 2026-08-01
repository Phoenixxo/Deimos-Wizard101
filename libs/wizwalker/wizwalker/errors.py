from typing import Union


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
