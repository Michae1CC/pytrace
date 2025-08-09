import socket

from typing import cast


def get_address_family_from_address(ip_address: str) -> socket.AddressFamily:
    import ipaddress

    parsed_address = ipaddress.ip_address(ip_address)

    if isinstance(parsed_address, ipaddress.IPv4Address):
        return socket.AF_INET
    elif isinstance(parsed_address, ipaddress.IPv6Address):
        return socket.AF_INET6

    raise ValueError("Unrecognised address family")


def get_dns_name_from_address(ip_address: str) -> str:
    DEFAULT_NAME_INFO_FLAGS = 0
    host_dns_name, _ = socket.getnameinfo((ip_address, 0), DEFAULT_NAME_INFO_FLAGS)
    return host_dns_name


def get_host_address(
    hostname: str,
    *,
    is_using_ipv6: bool = False,
) -> str:
    try:
        address_info = cast(
            list[
                tuple[
                    socket.AddressFamily, socket.SocketKind, int, str, tuple[str, int]
                ]
            ],
            socket.getaddrinfo(
                hostname, 0, family=socket.AF_INET6 if is_using_ipv6 else socket.AF_INET
            ),
        )
    except socket.gaierror as e:
        raise ValueError("Bad hostname provided", e)

    if len(address_info) == 0:
        raise ValueError(f"Could not find an address for {hostname}")

    (_, _, _, _, (ip_address, _)) = address_info[0]

    return cast(str, ip_address)


def is_ip_address(value: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False

    return True
