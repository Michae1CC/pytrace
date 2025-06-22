from __future__ import annotations

import argparse
import sys
import socket

from collections.abc import Sequence

from typing import Literal

from pytrace.const import DEFAULT_MAX_TTL
from pytrace.const import DEFAULT_NUMBER_OF_QUERIES
from pytrace.const import DEFAULT_PORT


def send_pings(
    address_family: socket.AddressFamily,
    iface: str | None,
    first_ttl: int,
    max_ttl: int,
    port: int,
    nqueries: int,
) -> None:
    # Create the socket
    sock = socket.socket(address_family, socket.SOCK_DGRAM)


def main(argv: Sequence[str] | None = None) -> None:
    argv = argv if argv is not None else sys.argv[1:]
    parser = argparse.ArgumentParser(prog="pytrace")

    parser.add_argument(
        "-s",
        "--src_addr",
        type=str,
        action="store_const",
        help=(
            "Use the following IP address (which must be given as an IP number, not a hostname) as the source address in outgoing probe packets.  On hosts with more than one IP address, this option"
            "can be used to force the source address to be something other than the IP address of the interface the probe packet is sent on.  If the IP address is not one of this machine's interface"
            "addresses, an error is returned and nothing is sent."
        ),
        default=None,
    )

    parser.add_argument(
        "-f",
        "--first_ttl",
        type=int,
        action="store_const",
        help=(
            "Set the initial time-to-live used in the first outgoing probe packet."
            "The default is 1, .i.e., start with the first hop"
        ),
        default="1",
    )

    parser.add_argument(
        "-m",
        "--max_ttl",
        type=int,
        action="store_const",
        help=(
            "Set the max time-to-live (max number of hops) used in outgoing probe"
            " packets. The default is net.inet.ip.ttl hops."
        ),
        default=f"{DEFAULT_MAX_TTL}",
    )

    parser.add_argument(
        "-p",
        "--port",
        type=int,
        action="store_const",
        help=(f"Sets the base port used in probes (default is {DEFAULT_PORT})."),
        default=f"{DEFAULT_PORT}",
    )

    parser.add_argument(
        "-q",
        "--nqueries",
        type=int,
        action="store_const",
        help=(
            "Set the number of queries per 'ttl' to nqueries"
            f" (default is {DEFAULT_NUMBER_OF_QUERIES} probes)"
        ),
        default=f"{DEFAULT_NUMBER_OF_QUERIES}",
    )

    args = parser.parse_args()

    address_family: socket.AddressFamily = (
        socket.AF_INET6 if args.ipv6 else socket.AF_INET
    )

    send_pings(
        address_family=address_family,
        iface=args.iface,
        first_ttl=args.first_ttl,
        max_ttl=args.max_ttl,
        port=args.port,
        nqueries=args.nqueries,
    )
