import socket
import struct
import sys

from typing import Final
from typing import TypedDict

from enum import IntEnum

from ._ip import is_ipv6


class ICMPTypes(IntEnum):
    ECHO_REPLY_MESSAGE = 0
    SOURCE_QUENCH_MESSAGE = 4
    REDIRECT_MESSAGE = 5
    ECHO_MESSAGE = 8
    TIME_TO_EXCEEDED = 11
    PARAMETER_PROBLEMS = 12
    TIME_STAMP_MESSAGE = 13
    TIME_STAMP_REPLY_MESSAGE = 14
    INFORMATION_REQUEST = 15
    INFORMATION_REPLY_MESSAGE = 16


class ICMPv6Types(IntEnum):
    ECHO_REPLY_MESSAGE = 128
    ECHO_MESSAGE = 129


class ICMPCodeType(TypedDict):
    code: int
    type: int


def _compute_icmp_checksum(icmp_packet_bytes: bytes) -> int:
    sum = 0
    count_to = (len(icmp_packet_bytes) // 2) * 2
    lo_byte: int = 0
    hi_byte: int = 0
    for count in range(0, count_to, 2):
        if sys.byteorder == "little":
            lo_byte = icmp_packet_bytes[count]
            hi_byte = icmp_packet_bytes[count + 1]
        else:
            lo_byte = icmp_packet_bytes[count + 1]
            hi_byte = icmp_packet_bytes[count]
        this_val = hi_byte * 256 + lo_byte
        sum = sum + this_val
        sum = sum & 0xFFFFFFFF

    if count_to < len(icmp_packet_bytes):
        sum = sum + icmp_packet_bytes[len(icmp_packet_bytes) - 1]
        sum = sum & 0xFFFFFFFF

    sum = (sum >> 16) + (sum & 0xFFFF)
    sum = sum + (sum >> 16)
    answer = ~sum
    answer = answer & 0xFFFF
    answer = answer >> 8 | (answer << 8 & 0xFF00)
    return answer


def create_icmp_echo_message(
    identifier: int,
    sequence_number: int,
    packet_data: bytes,
    family: socket.AddressFamily,
) -> bytes:
    ICMP_ECHO_MESSAGE_CODE: Final[int] = 0
    icmp_type: ICMPTypes | ICMPv6Types = (
        ICMPv6Types.ECHO_MESSAGE if is_ipv6(family) else ICMPTypes.ECHO_MESSAGE
    )
    initial_checksum: int = 0
    # Create a header with the checksum value set to 0 to compute the checksum
    # for the eventual header
    header_for_checksum: bytes = struct.pack(
        "!BBHHH",
        icmp_type,
        ICMP_ECHO_MESSAGE_CODE,
        initial_checksum,
        identifier,
        sequence_number,
    )
    checksum: int = _compute_icmp_checksum(bytes(header_for_checksum) + packet_data)
    header: bytes = struct.pack(
        "!BBHHH",
        icmp_type,
        ICMP_ECHO_MESSAGE_CODE,
        checksum,
        identifier,
        sequence_number,
    )
    return bytes(header) + packet_data


def get_icmp_header_values(icmp_message: bytes) -> ICMPCodeType:
    icmp_type, icmp_code = struct.unpack("!BB", icmp_message)
    return {"code": icmp_code, "type": icmp_type}
