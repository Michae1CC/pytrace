from __future__ import annotations

import argparse
import socket
import struct
import sys
import time

from collections.abc import Sequence

from pytrace.const import DEFAULT_MAX_TTL
from pytrace.const import DEFAULT_NUMBER_OF_QUERIES
from pytrace.const import DEFAULT_RESPONSE_WAIT_TIME_SEC
from pytrace.const import DEFAULT_PAUSE_TIME_MSEC
from pytrace.const import ICMP_PORT
from pytrace.const import ICMP_PORT_IPV6

from ._icmp import ICMPTypes
from ._icmp import ICMPv6Types
from ._icmp import create_icmp_echo_message
from ._icmp import get_icmp_header_values

from ._ip import get_address_family_from_ip_address
from ._ip import get_dns_name_from_ip_address
from ._ip import get_host_ip_addr
from ._ip import is_ip_address
from ._ip import is_ipv6


def _send_pings(
    address_family: socket.AddressFamily,
    first_ttl: int,
    max_ttl: int,
    nqueries: int,
    wait_time: int,
    pause_msec: int,
    host: str,
    packet_length: int,
    src_addr: str | None,
) -> None:
    socket_protocol: int = (
        socket.IPPROTO_ICMPV6 if is_ipv6(address_family) else socket.IPPROTO_ICMP
    )
    ip_header_size: int = 40 if is_ipv6(address_family) else 20
    icmp_echo_message_reply_header_size = 8

    print(
        f"pytrace to {host} ({host}), {max_ttl} hops max, {packet_length} bytes packets"
    )

    # Create the socket
    with socket.socket(address_family, socket.SOCK_RAW, socket_protocol) as sock:

        for ttl in range(first_ttl, max_ttl + 1):

            got_to_dest: bool = False

            sock.settimeout(wait_time)
            # Set the time-to-live of the ip packet
            if is_ipv6(address_family):
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IP_TTL, ttl)
            else:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)

            print(f"{ttl}", end="  ")

            for probe_num in range(nqueries):

                icmp_echo_message: bytes = create_icmp_echo_message(
                    identifier=1 + probe_num,
                    sequence_number=0,
                    packet_data=(
                        packet_length
                        - ip_header_size
                        - icmp_echo_message_reply_header_size
                    )
                    * b"\x00",
                    family=address_family,
                )

                if probe_num != 0:
                    time.sleep(pause_msec)

                packet_sent_time: float = time.perf_counter()

                if is_ipv6(address_family):
                    sock.sendto(bytes(icmp_echo_message), (host, ICMP_PORT_IPV6, 0, 0))
                else:
                    # Ports are not used for ICMP messages, just use a port of 0
                    sock.sendto(bytes(icmp_echo_message), (host, 0))

                try:
                    (returned_data, response_server_address) = sock.recvfrom(1024)
                    if is_ipv6(address_family):
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

                src_dns_name: str = get_dns_name_from_ip_address(
                    response_server_ip_address
                )
                src_display_name: str = src_dns_name or response_server_ip_address

                if probe_num == 0:
                    print(
                        f"{src_display_name} ({response_server_ip_address})",
                        end="  ",
                    )

                print(
                    "{:.3f} ms".format(
                        (packet_received_time - packet_sent_time) * 1000
                    ),
                    end="  ",
                    flush=True,
                )

                if is_ipv6(address_family):
                    if (
                        icmp_response_header_values["type"]
                        == ICMPv6Types.ECHO_REPLY_MESSAGE
                    ):
                        got_to_dest = True
                else:
                    if (
                        icmp_response_header_values["type"]
                        == ICMPTypes.ECHO_REPLY_MESSAGE
                    ):
                        got_to_dest = True

            print()

            if got_to_dest:
                break


def main(argv: Sequence[str] | None = None) -> None:

    # python -m pytrace -q 1 -w 1 '2404:6800:4006:814::200e'
    # python -m pytrace -q 1 -w 1 128.32.131.22
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
        type=int,
        default=48,
    )

    args = parser.parse_args()

    src_addr: str | None = args.src_addr
    try:
        address_family = socket.AF_INET6
        # address_family: socket.AddressFamily = (
        #     socket.AF_INET
        #     if src_addr is None
        #     else get_address_family_from_ip_address(src_addr)
        # )
    except ValueError:
        parser.print_help()
        sys.exit(1)

    host_ip_addr: str = (
        args.host
        if is_ip_address(args.host)
        else get_host_ip_addr(args.host, address_family)
    )

    _send_pings(
        address_family=address_family,
        first_ttl=args.first_ttl,
        max_ttl=args.max_ttl,
        nqueries=args.nqueries,
        wait_time=args.wait_time,
        pause_msec=args.pause_msecs,
        host=host_ip_addr,
        packet_length=args.packet_length,
        src_addr=src_addr,
    )
