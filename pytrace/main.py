from __future__ import annotations

import argparse
import sys
import socket
import struct

from collections.abc import Sequence

from typing import Final
from typing import Literal

from pytrace.const import DEFAULT_MAX_TTL
from pytrace.const import DEFAULT_NUMBER_OF_QUERIES
from pytrace.const import DEFAULT_RESPONSE_WAIT_TIME_SEC
from pytrace.const import DEFAULT_PAUSE_TIME_MSEC
from pytrace.const import DEFAULT_PORT


class ICMPEchoMessage:

    _ICMP_ECHO_CODE: Final[int] = 8

    def __init__(self, identifier: int, sequence_number: int) -> None:
        self._identifier = identifier
        self._sequence_number = sequence_number

    @classmethod
    def _compute_icmp_checksum(cls, icmp_packet_bytes: bytes) -> int:
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

    def __bytes__(self) -> bytes:
        packet_data: bytes = b"\0" * 20
        initial_checksum: int = 0
        header_for_checksum: bytes = struct.pack(
            "!BBHHH",
            self._ICMP_ECHO_CODE,
            0,
            initial_checksum,
            self._identifier,
            self._sequence_number,
        )
        checksum = self._compute_icmp_checksum(bytes(header_for_checksum) + packet_data)
        header: bytes = struct.pack(
            "!BBHHH",
            self._ICMP_ECHO_CODE,
            0,
            checksum,
            self._identifier,
            self._sequence_number,
        )
        return bytes(header) + packet_data


def _get_address_family_from_ip_address(ip_address: str) -> socket.AddressFamily:
    import ipaddress

    parsed_address = ipaddress.ip_address(ip_address)

    return (
        socket.AF_INET
        if isinstance(parsed_address, ipaddress.IPv4Address)
        else socket.AF_INET6
    )


def _send_pings(
    address_family: socket.AddressFamily,
    first_ttl: int,
    max_ttl: int,
    port: int,
    nqueries: int,
    src_addr: str | None,
) -> None:
    socket_protocol: int = (
        socket.IPPROTO_ICMP
        if address_family == socket.AF_INET
        else socket.IPPROTO_ICMPV6
    )
    print(f"socket.AF_INET {socket.AF_INET}")
    print(f"socket.AF_INET6 {socket.AF_INET6}")
    print(f"socket.IPPROTO_ICMP {socket.IPPROTO_ICMP}")
    print(f"socket.IPPROTO_ICMPV6 {socket.IPPROTO_ICMPV6}")

    print(address_family)
    print(socket_protocol)

    # Create the socket
    with socket.socket(address_family, socket.SOCK_DGRAM, socket_protocol) as sock:
        icmp_echo_message = ICMPEchoMessage(identifier=1, sequence_number=1)
        sock.sendto(bytes(icmp_echo_message), ("1.1.1.1", 0))
        try:
            sock.settimeout(1)  # Timeout for receiving reply
            recv_packet, addr = sock.recvfrom(1024)
            icmp_header = recv_packet[20:28]  # IP header is usually 20 bytes
            icmp_type, icmp_code, _, _, _ = struct.unpack("!BBHHH", icmp_header)

            if icmp_type == 0 and icmp_code == 0:  # Echo Reply
                print(f"Received ICMP Echo Reply from {addr[0]}")
            else:
                print(f"Received unexpected ICMP type/code: {icmp_type}/{icmp_code}")
        except socket.timeout:
            print(f"Timeout waiting for reply")
        except Exception as e:
            print(f"Error receiving reply: {e}")


def main(argv: Sequence[str] | None = None) -> None:
    argv = argv if argv is not None else sys.argv[1:]
    parser = argparse.ArgumentParser(prog="pytrace")

    parser.add_argument(
        "-s",
        "--src_addr",
        type=str,
        help=(
            "Use the following IP address (which must be given as an IP number, "
            "not a hostname) as the source address in outgoing probe packets. "
            "On hosts with more than one IP address, this option can be used "
            "to force the source address to be something other than the IP "
            "address of the interface the probe packet is sent on.  If the IP "
            "address is not one of this machine's interface addresses, an "
            "error is returned and nothing is sent."
        ),
        default=None,
    )

    parser.add_argument(
        "-f",
        "--first_ttl",
        type=int,
        help=(
            "Set the initial time-to-live used in the first outgoing probe packet. "
            "The default is 1, .i.e., start with the first hop."
        ),
        default="1",
    )

    parser.add_argument(
        "-m",
        "--max_ttl",
        type=int,
        help=(
            "Set the max time-to-live (max number of hops) used in outgoing probe "
            f"packets. The default is {DEFAULT_MAX_TTL} hops."
        ),
        default=f"{DEFAULT_MAX_TTL}",
    )

    parser.add_argument(
        "-p",
        "--port",
        type=int,
        help=(f"Sets the base port used in probes (default is {DEFAULT_PORT})."),
        default=f"{DEFAULT_PORT}",
    )

    parser.add_argument(
        "-q",
        "--nqueries",
        type=int,
        help=(
            "Set the number of queries per 'ttl' to nqueries "
            f"(default is {DEFAULT_NUMBER_OF_QUERIES} probes)"
        ),
        default=f"{DEFAULT_NUMBER_OF_QUERIES}",
    )

    parser.add_argument(
        "-w",
        type=int,
        help=(
            "Set the time (in seconds) to wait for a response to a probe "
            f"(default {DEFAULT_RESPONSE_WAIT_TIME_SEC} sec.)."
        ),
        default=f"{DEFAULT_RESPONSE_WAIT_TIME_SEC}",
    )

    parser.add_argument(
        "-z",
        type=int,
        help=(
            f"Set the time (in milliseconds) to pause between probes (default {DEFAULT_PAUSE_TIME_MSEC}). "
            "Some systems such as Solaris and routers such as Ciscos rate limit ICMP messages. "
            "A good value to use with this is 500 (e.g. 1/2 second)."
        ),
        default=f"{DEFAULT_PAUSE_TIME_MSEC}",
    )

    parser.add_argument(
        "host",
        nargs=1,
        type=str,
    )

    parser.add_argument(
        "packet_length",
        nargs="?",
        type=str,
        default=40,
    )

    args = parser.parse_args()

    src_addr: str | None = args.src_addr
    try:
        address_family: socket.AddressFamily = (
            socket.AF_INET
            if src_addr is None
            else _get_address_family_from_ip_address(src_addr)
        )
    except ValueError:
        parser.print_help()
        sys.exit(1)

    _send_pings(
        address_family=address_family,
        first_ttl=args.first_ttl,
        max_ttl=args.max_ttl,
        port=args.port,
        nqueries=args.nqueries,
        src_addr=src_addr,
    )
