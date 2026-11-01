"""Address validation and normalization shared by imports and storage."""

import ipaddress


def normalize_ip(value: str | None) -> str | None:
    """Return the canonical IPv4/IPv6 spelling, or None for invalid input."""
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def valid_ip(value: str | None) -> bool:
    return normalize_ip(value) is not None
