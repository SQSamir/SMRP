"""Binary packet structures for the SMRP wire protocol."""
from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import IntEnum


SMRP_MAGIC = 0x534D5250
SMRP_VERSION = 0x01
HEADER_LEN = 54
MAX_PAYLOAD = 1280
AUTH_TAG_LEN = 16


class PacketType(IntEnum):
    HELLO          = 0x01
    HELLO_ACK      = 0x02
    DATA           = 0x03
    ACK            = 0x04
    KEEPALIVE      = 0x05
    KEEPALIVE_ACK  = 0x06
    KEY_UPDATE     = 0x07
    KEY_UPDATE_ACK = 0x08
    FIN            = 0x09
    ERROR          = 0x0A


# Header format: magic(4) version(1) type(1) flags(1) reserved(1)
#                session_id(8) seq(8) ack(8) timestamp_us(8) payload_len(2)
# = 42 bytes; padded with 12 reserved bytes to reach HEADER_LEN=54
_HEADER_STRUCT = struct.Struct("!IBBBB 8s QQQ H 12x")
assert _HEADER_STRUCT.size == HEADER_LEN


@dataclass
class SmrpHeader:
    """Decoded representation of a 54-byte SMRP header."""

    magic: int
    version: int
    packet_type: PacketType
    flags: int
    reserved: int
    session_id: bytes
    sequence_number: int
    ack_number: int
    timestamp_us: int
    payload_len: int

    @classmethod
    def parse(cls, data: bytes) -> "SmrpHeader":
        if len(data) < HEADER_LEN:
            raise ValueError(f"buffer too short: {len(data)} < {HEADER_LEN}")
        (
            magic, version, ptype, flags, reserved,
            session_id, seq, ack, ts, plen
        ) = _HEADER_STRUCT.unpack_from(data)
        if magic != SMRP_MAGIC:
            raise ValueError(f"invalid magic: 0x{magic:08X}")
        if version != SMRP_VERSION:
            raise ValueError(f"unsupported version: 0x{version:02X}")
        return cls(
            magic=magic,
            version=version,
            packet_type=PacketType(ptype),
            flags=flags,
            reserved=reserved,
            session_id=session_id,
            sequence_number=seq,
            ack_number=ack,
            timestamp_us=ts,
            payload_len=plen,
        )
