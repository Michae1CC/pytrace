import socket

from typing import Final

DEFAULT_PORT: Final[int] = 33_434

DEFAULT_NUMBER_OF_QUERIES: Final[int] = 3

DEFAULT_MAX_TTL: Final[int] = socket.socket(
    socket.AF_INET, socket.SOCK_DGRAM
).getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
