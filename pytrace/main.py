from __future__ import annotations

import argparse
import socket
import struct
import sys
import time

from typing import Final

from collections.abc import Sequence

from pytrace.const import DEFAULT_MAX_TTL
from pytrace.const import DEFAULT_NUMBER_OF_QUERIES
from pytrace.const import DEFAULT_RESPONSE_WAIT_TIME_SEC
from pytrace.const import DEFAULT_PAUSE_TIME_MSEC
from pytrace.const import PROGRAM_NAME

from ._icmp import ICMPDestinationUnreachableCodes
from ._icmp import ICMPv6DestinationUnreachableCodes
from ._icmp import ICMPTypes
from ._icmp import ICMPv6Types
from ._icmp import create_icmp_echo_message
from ._icmp import get_icmp_header_values

from ._ip import get_address_family_from_address
from ._ip import get_dns_name_from_address
from ._ip import get_host_address
from ._ip import is_ip_address


def _send_pings(
    first_ttl: int,
    max_ttl: int,
    n_queries: int,
    wait_time: int,
    pause_msec: int,
    packet_length: int,
    host: str,
    host_address: str,
    src_address: str | None,
) -> None:

    address_family: socket.AddressFamily = get_address_family_from_address(host_address)
    is_using_ipv6: bool = address_family == socket.AddressFamily.AF_INET6
    icmp_protocol: int = socket.IPPROTO_ICMPV6 if is_using_ipv6 else socket.IPPROTO_ICMP
    ip_protocol: int = socket.IPPROTO_IPV6 if is_using_ipv6 else socket.IPPROTO_IP
    ip_header_size: int = 40 if is_using_ipv6 else 20
    icmp_echo_message_reply_header_size = 8

    print(
        f"pytrace to {host_address} ({host}), {max_ttl} hops max, {packet_length} byte packets"
    )

    # Create the socket
    with socket.socket(address_family, socket.SOCK_RAW, icmp_protocol) as sock:

        for ttl in range(first_ttl, max_ttl + 1):

            unreachable: int = 0
            got_to_dest: bool = False

            if src_address is not None:
                sock.bind((src_address, 0))

            sock.settimeout(wait_time)
            # Set the time-to-live of the ip packet
            sock.setsockopt(ip_protocol, socket.IP_TTL, ttl)

            print(f"{ttl}", end="  ")

            for probe_num in range(n_queries):

                icmp_echo_message: bytes = create_icmp_echo_message(
                    identifier=1 + probe_num,
                    sequence_number=0,
                    packet_data=(
                        packet_length
                        - ip_header_size
                        - icmp_echo_message_reply_header_size
                    )
                    * b"\x00",
                    is_using_ipv6=is_using_ipv6,
                )

                if probe_num != 0:
                    time.sleep(pause_msec)

                packet_sent_time: float = time.perf_counter()

                # Ports are not used for ICMP messages, just use a port of 0
                if is_using_ipv6:
                    sock.sendto(bytes(icmp_echo_message), (host_address, 0, 0, 0))
                else:
                    sock.sendto(bytes(icmp_echo_message), (host_address, 0))

                try:
                    (returned_data, response_server_address) = sock.recvfrom(
                        512 + packet_length
                    )
                    if is_using_ipv6:
                        (response_server_ip_address, _, _, _) = response_server_address
                    else:
                        (
                            response_server_ip_address,
                            _,
                        ) = response_server_address
                    packet_received_time: float = time.perf_counter()
                except socket.timeout:
                    print("*", end="  ", flush=True)
                    continue

                try:
                    # https://datatracker.ietf.org/doc/html/rfc791#section-3.1
                    icmp_echo_message_reply_header_slice: slice = slice(
                        ip_header_size,
                        # The type and code appear in the first 2 bytes
                        ip_header_size + 2,
                    )
                    icmp_header: bytes = returned_data[
                        icmp_echo_message_reply_header_slice
                    ]
                    icmp_response_header_values = get_icmp_header_values(icmp_header)
                except struct.error:
                    # Sometimes the ip header is stripped for us
                    icmp_response_header_values = get_icmp_header_values(
                        returned_data[0:2]
                    )

                icmp_type: int = icmp_response_header_values["type"]
                icmp_code: int = icmp_response_header_values["code"]

                src_dns_name: str = get_dns_name_from_address(
                    response_server_ip_address
                )
                src_display_name: str = src_dns_name or response_server_ip_address

                if probe_num == 0:
                    print(
                        f"{src_display_name} ({response_server_ip_address})",
                        end=" ",
                    )

                print(
                    "{:.3f} ms".format(
                        (packet_received_time - packet_sent_time) * 1000
                    ),
                    end=" ",
                    flush=True,
                )

                if is_using_ipv6:
                    match icmp_type:
                        case ICMPv6Types.ECHO_REPLY_MESSAGE:
                            got_to_dest = True
                        case ICMPv6Types.TIME_TO_EXCEEDED:
                            continue
                        case ICMPv6Types.DESTINATION_UNREACHABLE:
                            match icmp_code:
                                case ICMPv6DestinationUnreachableCodes.PORT_UNREACHABLE:
                                    got_to_dest = True
                                case ICMPv6DestinationUnreachableCodes.NO_ROUTE:
                                    print("!N", end=" ", flush=True)
                                    unreachable += 1
                                case (
                                    ICMPv6DestinationUnreachableCodes.ADDRESS_UNREACHABLE
                                ):
                                    print("!H", end=" ", flush=True)
                                    unreachable += 1
                                case (
                                    ICMPv6DestinationUnreachableCodes.DEST_ADMINISTRATIVELY_PROHIBITED
                                ):
                                    print("!S", end=" ", flush=True)
                                    unreachable += 1
                                case _:
                                    print(f"!<{icmp_code}>", end=" ", flush=True)
                                    unreachable += 1
                else:
                    match icmp_type:
                        case ICMPTypes.ECHO_REPLY_MESSAGE:
                            got_to_dest = True
                        case ICMPTypes.TIME_TO_EXCEEDED:
                            continue
                        case ICMPTypes.DESTINATION_UNREACHABLE:
                            match icmp_code:
                                case ICMPDestinationUnreachableCodes.NET_UNREACHABLE:
                                    print("!N", end=" ", flush=True)
                                    unreachable += 1
                                case ICMPDestinationUnreachableCodes.HOST_UNREACHABLE:
                                    print("!H", end=" ", flush=True)
                                    unreachable += 1
                                case (
                                    ICMPDestinationUnreachableCodes.PROTOCOL_UNREACHABLE
                                ):
                                    print("!P", end=" ", flush=True)
                                    got_to_dest = True
                                case (
                                    ICMPDestinationUnreachableCodes.FRAGMENTATION_NEEDED
                                ):
                                    print("!F", end=" ", flush=True)
                                    unreachable += 1
                                case (
                                    ICMPDestinationUnreachableCodes.DEST_HOST_UNKNOWN
                                    | ICMPDestinationUnreachableCodes.DEST_NETWORK_UNKNOWN
                                ):
                                    print("!U", end=" ", flush=True)
                                    unreachable += 1
                                case (
                                    ICMPDestinationUnreachableCodes.SOURCE_ROUTE_FAILED
                                ):
                                    print("!S", end=" ", flush=True)
                                    unreachable += 1
                                case ICMPDestinationUnreachableCodes.NETWORK_PROHIBITED:
                                    print("!A", end=" ", flush=True)
                                    unreachable += 1
                                case (
                                    ICMPDestinationUnreachableCodes.HOST_PRECEDENCE_VIOLATION
                                ):
                                    print("!V", end=" ", flush=True)
                                    unreachable += 1
                                case ICMPDestinationUnreachableCodes.PRECEDENCE_CUTOFF:
                                    print("!C", end=" ", flush=True)
                                    unreachable += 1
                                case _:
                                    print(f"!<{icmp_code}>", end=" ", flush=True)
                                    unreachable += 1
                print(" ", end="", flush=True)

            print()

            if got_to_dest or (unreachable > 0 and unreachable >= n_queries - 1):
                break


def _log_program_error(message: str) -> None:
    print(f"{PROGRAM_NAME}: {message}", file=sys.stderr)


def _run(args: argparse.Namespace) -> int:

    first_ttl: Final[int] = args.first_ttl
    max_ttl: Final[int] = args.max_ttl
    n_queries: Final[int] = args.n_queries
    wait_time: Final[int] = args.wait_time
    pause_msecs: Final[int] = args.pause_msecs
    packet_length: Final[int] = args.packet_length
    host: Final[str] = args.host
    src_address: Final[str | None] = args.src_address

    packet_length_min_value: Final[int] = 28
    first_ttl_max_value: Final[int] = 255
    max_ttl_max_value: Final[int] = 255
    wait_time_max_value_seconds: Final[int] = 60 * 60 * 24
    packet_length_max_value: Final[int] = 32_768

    try:
        host_address: Final[str] = (
            host if is_ip_address(args.host) else get_host_address(args.host)
        )
    except ValueError:
        _log_program_error(f"unknown host {host}")
        return 1

    for value, human_readable_name in zip(
        [first_ttl, max_ttl, n_queries, wait_time],
        ["first ttl", "max ttl", "nprobes", "wait time"],
    ):
        if not (0 < value):
            _log_program_error(f"{human_readable_name} must be > 0")
            return 1

    if not (0 <= pause_msecs):
        _log_program_error((f"pause msecs must be >= 0"))
        return 1

    if not (packet_length_min_value <= packet_length):
        _log_program_error((f"packet_length must be >= {packet_length_min_value}"))
        return 1

    if not (first_ttl <= first_ttl_max_value):
        _log_program_error((f"first ttl must be <= {first_ttl_max_value}"))
        return 1

    if not (max_ttl <= max_ttl_max_value):
        _log_program_error((f"max ttl must be <= {max_ttl_max_value}"))
        return 1

    if not (wait_time <= wait_time_max_value_seconds):
        _log_program_error((f"wait time must be <= {wait_time_max_value_seconds}"))
        return 1

    if not (packet_length <= packet_length_max_value):
        _log_program_error((f"packet length must be <= {packet_length_max_value}"))
        return 1

    if src_address is not None and not is_ip_address(src_address):
        _log_program_error(("src addr must be an IPv4 or IPv6 address"))
        return 1

    src_address_family = (
        None if src_address is None else get_address_family_from_address(src_address)
    )

    # This should be used to query the host address name
    host_address_family: socket.AddressFamily = get_address_family_from_address(
        host_address
    )

    if src_address_family is not None and src_address_family != host_address_family:
        _log_program_error(f"src address family and host address family do not match")
        sys.exit(1)

    _send_pings(
        first_ttl=first_ttl,
        max_ttl=max_ttl,
        n_queries=n_queries,
        wait_time=wait_time,
        pause_msec=pause_msecs,
        packet_length=packet_length,
        host=host,
        host_address=host_address,
        src_address=src_address,
    )

    return 0


def main(argv: Sequence[str] | None = None) -> int:

    # python -m pytrace -q 1 -w 1 '2404:6800:4006:814::200e'
    # python -m pytrace -q 1 -w 1 128.32.131.22
    # 128.32.131.22

    argv = argv if argv is not None else sys.argv[1:]
    parser = argparse.ArgumentParser(prog=PROGRAM_NAME)

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
        dest="src_address",
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
        "-q",
        type=int,
        help=(
            "Set the number of queries per 'ttl' to nqueries "
            f"(default is {DEFAULT_NUMBER_OF_QUERIES} probes)"
        ),
        default=f"{DEFAULT_NUMBER_OF_QUERIES}",
        metavar="nqueries",
        dest="n_queries",
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
        type=int,
        default=40,
    )

    args = parser.parse_args()

    return _run(args)
