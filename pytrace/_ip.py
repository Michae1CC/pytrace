import socket

from typing import cast


def get_address_family_from_ip_address(ip_address: str) -> socket.AddressFamily:
    import ipaddress

    parsed_address = ipaddress.ip_address(ip_address)

    print(parsed_address)
    print(type(parsed_address))

    if isinstance(parsed_address, ipaddress.IPv4Address):
        return socket.AF_INET
    elif isinstance(parsed_address, ipaddress.IPv6Address):
        return socket.AF_INET6

    raise ValueError("Unrecognised address family")


def get_dns_name_from_ip_address(ip_address: str) -> str:
    DEFAULT_NAME_INFO_FLAGS = 0
    host_dns_name, _ = socket.getnameinfo((ip_address, 0), DEFAULT_NAME_INFO_FLAGS)
    return host_dns_name


def get_host_ip_addr(host: str, family: socket.AddressFamily) -> str:
    addr_info = cast(
        list[tuple[socket.AddressFamily, socket.SocketKind, int, str, tuple[str, int]]],
        socket.getaddrinfo(host, 0, family=socket.AF_INET),
    )

    if len(addr_info) == 0:
        raise ValueError(f"Could not find an address for {host}")

    (_, _, _, _, (ip_addr, _)) = addr_info[0]

    return cast(str, ip_addr)


def is_ip_address(host: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False

    return True


def is_ipv6(family: socket.AddressFamily) -> bool:

    return family == socket.AddressFamily.AF_INET6
