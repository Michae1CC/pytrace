import socket

from typing import Final
from typing import Literal

DEFAULT_NUMBER_OF_QUERIES: Final[int] = 3
DEFAULT_RESPONSE_WAIT_TIME_SEC: Final[int] = 5
DEFAULT_PAUSE_TIME_MSEC: Final[int] = 0
DEFAULT_MAX_TTL: Final[int] = socket.socket(
    socket.AF_INET, socket.SOCK_DGRAM
).getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
PROGRAM_NAME: Final[Literal["pytrace"]] = "pytrace"
