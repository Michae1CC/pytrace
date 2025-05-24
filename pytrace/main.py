from __future__ import annotations

import argparse
import sys
import socket

from collections.abc import Sequence

from pytrace.const import DEFAULT_PORT
from pytrace.const import DEFAULT_NUMBER_OF_QUERIES


def main(argv: Sequence[str] | None = None) -> None:
    argv = argv if argv is not None else sys.argv[1:]
    parser = argparse.ArgumentParser(prog="pytrace")

    parser.add_argument(
        "-i",
        "--iface",
        action="iface",
        help=(
            "Specify a network interface to obtain the source IP address for"
            " outgoing probe packets."
        ),
        default=1,
    )

    parser.add_argument(
        "-f",
        "--first_ttl",
        action="first_ttl",
        help=(
            "Set the initial time-to-live used in the first outgoing probe packet."
            "The default is 1, .i.e., start with the first hop"
        ),
        default=1,
    )

    parser.add_argument(
        "-m",
        "--max_ttl",
        action="max_ttl",
        help=(
            "Set the max time-to-live (max number of hops) used in outgoing probe"
            " packets. The default is net.inet.ip.ttl hops."
        ),
        default=socket.IP_TTL,
    )

    parser.add_argument(
        "-p",
        "--port",
        action="port",
        help=(f"Sets the base port used in probes (default is {DEFAULT_PORT})."),
        default=DEFAULT_PORT,
    )

    parser.add_argument(
        "-q",
        "--nqueries",
        action="nqueries",
        help=(
            "Set the number of queries per 'ttl' to nqueries"
            f" (default is {DEFAULT_NUMBER_OF_QUERIES} probes)"
        ),
        default=DEFAULT_NUMBER_OF_QUERIES,
    )
