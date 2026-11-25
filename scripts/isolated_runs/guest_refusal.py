"""Finite, nonsecret diagnostics for guest proof and its existing-only bridge."""

import contextlib
import functools
import json
import sys

from .state import RunError, existing_lock


SCHEMA = "idarsi.scenario-context/guest-refusal-v1"
CODES = frozenset({
    "LOCK_BUSY", "NATIVE_IDENTITY", "NETWORK_OBSERVATION", "SSH_MAPPING",
    "READONLY_STATE", "AUTHORITY_PARSE", "PROCESS_SUPERVISION", "UNKNOWN_REFUSAL",
})
LIMIT = 512


class GuestRefusal(RunError):
    """Carry only a closed category, never an exception message or context."""

    def __init__(self, code: str):
        if not isinstance(code, str) or code not in CODES:
            raise ValueError("Invalid guest refusal category")
        self.code = code
        super().__init__(code)


@contextlib.contextmanager
def boundary(code: str):
    """Tag expected failures at an explicitly reviewed authoritative boundary."""
    try:
        yield
    except GuestRefusal:
        raise
    except (RunError, OSError, ValueError, KeyError, TypeError, AttributeError):
        raise GuestRefusal(code) from None


def tagged(code: str):
    def decorate(function):
        @functools.wraps(function)
        def invoke(*args, **kwargs):
            with boundary(code):
                return function(*args, **kwargs)
        return invoke
    return decorate


def checked(code: str, function, *args, **kwargs):
    with boundary(code):
        return function(*args, **kwargs)


@contextlib.contextmanager
def proof_lock(path):
    """Only a real existing-lock acquisition can report LOCK_BUSY."""
    manager = existing_lock(path)
    try:
        manager.__enter__()
    except RunError as exc:
        code = "LOCK_BUSY" if exc.args == ("recovery_lock_busy",) else "READONLY_STATE"
        raise GuestRefusal(code) from None
    except OSError:
        raise GuestRefusal("READONLY_STATE") from None
    try:
        yield
    except BaseException:
        checked("READONLY_STATE", manager.__exit__, *sys.exc_info())
        raise
    else:
        checked("READONLY_STATE", manager.__exit__, None, None, None)


def emit(error: Exception, *, stream=None) -> None:
    """Never stringify unknown errors (even __str__ may itself be unsafe)."""
    code = error.code if type(error) is GuestRefusal else "UNKNOWN_REFUSAL"
    if not isinstance(code, str) or code not in CODES:
        code = "UNKNOWN_REFUSAL"
    print(json.dumps({"schema": SCHEMA, "code": code}, sort_keys=True), file=sys.stderr if stream is None else stream)


def parse(value):
    """Recognize only one bounded exact envelope, otherwise UNKNOWN."""
    try:
        if isinstance(value, bytes):
            if len(value) > LIMIT:
                return "UNKNOWN_REFUSAL"
            value = value.decode("utf-8")
        if not isinstance(value, str) or len(value.encode("utf-8")) > LIMIT:
            return "UNKNOWN_REFUSAL"

        def pairs(items):
            result = {}
            for key, item in items:
                if key in result:
                    raise ValueError("duplicate")
                result[key] = item
            return result

        def constant(_value):
            raise ValueError("constant")

        data = json.loads(value, object_pairs_hook=pairs, parse_constant=constant)
        if (
            isinstance(data, dict) and set(data) == {"schema", "code"}
            and data["schema"] == SCHEMA and isinstance(data["code"], str)
            and data["code"] in CODES
        ):
            return data["code"]
    except (ValueError, TypeError, RecursionError):
        pass
    return "UNKNOWN_REFUSAL"
