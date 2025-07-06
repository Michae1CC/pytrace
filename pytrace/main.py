from __future__ import annotations

import argparse
import socket
import struct
import sys
import time

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
    wait_time: int,
    pause_msec: int,
    host: str,
    packet_length: int | None,
    src_addr: str | None,
) -> None:
    socket_protocol: int = (
        socket.IPPROTO_ICMP
        if address_family == socket.AF_INET
        else socket.IPPROTO_ICMPV6
    )
    # print(f"socket.AF_INET {socket.AF_INET}")
    # print(f"socket.AF_INET6 {socket.AF_INET6}")
    # print(f"socket.IPPROTO_ICMP {socket.IPPROTO_ICMP}")
    # print(f"socket.IPPROTO_ICMPV6 {socket.IPPROTO_ICMPV6}")

    # print(address_family)
    # print(socket_protocol)

    print(
        f"pytrace to {host} ({host}), {max_ttl} hops max, {packet_length} bytes packets"
    )

    for ttl in range(first_ttl, max_ttl + 1):

        got_to_dest: bool = False

        print(f"{ttl}", end=" ")

        # Create the socket
        with socket.socket(address_family, socket.SOCK_DGRAM, socket_protocol) as sock:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
            icmp_echo_message = ICMPEchoMessage(identifier=1, sequence_number=0)
            sock.settimeout(1)  # Timeout for receiving reply

            for prod_num in range(nqueries):

                if prod_num != 0:
                    time.sleep(pause_msec)

                packet_sent_time: float = time.perf_counter()
                sock.sendto(bytes(icmp_echo_message), (host, 0))

                try:
                    recv_packet, addr = sock.recvfrom(1024)
                    packet_received_time: float = time.perf_counter()
                except socket.timeout:
                    print(" *", end="")
                    continue

                # https://datatracker.ietf.org/doc/html/rfc791#section-3.1
                ip_header: bytes = recv_packet[0:20]
                ip_header_struct = struct.unpack("!BBHHHBBH4s4s", ip_header)
                icmp_header = recv_packet[20:28]  # ICMP header is usually 20 bytes
                icmp_type, icmp_code, _, _, _ = struct.unpack("!BBHHH", icmp_header)

                source_address = socket.inet_ntoa(ip_header_struct[8])

                if prod_num == 0:
                    print(f"{source_address} ({source_address})", end=" ")

                print(
                    "{:.3f} ms".format(
                        (packet_received_time - packet_sent_time) * 1000
                    ),
                    end=" ",
                )

                if icmp_type == 0:
                    got_to_dest = True

        print()

        if got_to_dest:
            break


def main(argv: Sequence[str] | None = None) -> None:

    # 128.32.131.22

    argv = argv if argv is not None else sys.argv[1:]
    parser = argparse.ArgumentParser(prog="pytrace")

    parser.add_argument(
        "-s",
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
        metavar="src_addr",
        dest="src_addr",
    )

    parser.add_argument(
        "-f",
        type=int,
        help=(
            "Set the initial time-to-live used in the first outgoing probe packet. "
            "The default is 1, .i.e., start with the first hop."
        ),
        default="1",
        metavar="first_ttl",
        dest="first_ttl",
    )

    parser.add_argument(
        "-m",
        type=int,
        help=(
            "Set the max time-to-live (max number of hops) used in outgoing probe "
            f"packets. The default is {DEFAULT_MAX_TTL} hops."
        ),
        default=f"{DEFAULT_MAX_TTL}",
        metavar="max_ttl",
        dest="max_ttl",
    )

    parser.add_argument(
        "-p",
        type=int,
        help=(f"Sets the base port used in probes (default is {DEFAULT_PORT})."),
        default=f"{DEFAULT_PORT}",
        metavar="port",
        dest="port",
    )

    parser.add_argument(
        "-q",
        type=int,
        help=(
            "Set the number of queries per 'ttl' to nqueries "
            f"(default is {DEFAULT_NUMBER_OF_QUERIES} probes)"
        ),
        default=f"{DEFAULT_NUMBER_OF_QUERIES}",
        metavar="nqueries",
        dest="nqueries",
    )

    parser.add_argument(
        "-w",
        type=int,
        help=(
            "Set the time (in seconds) to wait for a response to a probe "
            f"(default {DEFAULT_RESPONSE_WAIT_TIME_SEC} sec.)."
        ),
        default=f"{DEFAULT_RESPONSE_WAIT_TIME_SEC}",
        metavar="waittime",
        dest="wait_time",
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
        metavar="pausemsecs",
        dest="pause_msecs",
    )

    parser.add_argument("host", type=str)

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
        wait_time=args.wait_time,
        pause_msec=args.pause_msecs,
        host=args.host,
        packet_length=args.packet_length,
        src_addr=src_addr,
    )
