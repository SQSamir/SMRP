"""Session state machine types for the SMRP Python prototype."""
from __future__ import annotations

from enum import Enum, auto
import os


SESSION_ID_LEN = 8


class SessionState(Enum):
    """Lifecycle states of an SMRP session."""

    INIT             = auto()
    HELLO_SENT       = auto()
    HELLO_RECEIVED   = auto()
    HANDSHAKING      = auto()
    ESTABLISHED      = auto()
    KEY_UPDATE       = auto()
    CLOSING          = auto()
    CLOSED           = auto()
    ERROR            = auto()


class SessionId:
    """Opaque 8-byte session identifier."""

    __slots__ = ("_bytes",)

    def __init__(self, raw: bytes) -> None:
        if len(raw) != SESSION_ID_LEN:
            raise ValueError(f"SessionId must be {SESSION_ID_LEN} bytes")
        self._bytes = raw

    @classmethod
    def generate(cls) -> "SessionId":
        return cls(os.urandom(SESSION_ID_LEN))

    def __bytes__(self) -> bytes:
        return self._bytes

    def __repr__(self) -> str:
        return f"SessionId({self._bytes.hex()})"
