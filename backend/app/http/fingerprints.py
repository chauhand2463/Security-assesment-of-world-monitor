"""HTTP/TLS fingerprint helpers (Phase 5).

Native, deterministic inspection: TLS certificate/protocol metadata and light
server/technology hints.  Everything degrades to ``None`` on failure -- a failed
probe is never converted into a claim.
"""
from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlsplit

# Header -> technology hint map (server-side disclosure).
_TECH_HINTS = {
    "server": "server",
    "x-powered-by": "framework",
    "x-aspnet-version": "aspnet",
    "x-generator": "generator",
    "x-drupal-cache": "drupal",
    "x-shopify-stage": "shopify",
    "x-vercel-id": "vercel",
}


def host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def port_of(url: str, default: int | None = None) -> int | None:
    try:
        parts = urlsplit(url)
    except ValueError:
        return default
    if parts.port:
        return parts.port
    if parts.scheme == "https":
        return 443
    if parts.scheme == "http":
        return 80
    return default


def fetch_tls_info(url: str, timeout: float = 8.0) -> dict | None:
    """Return certificate/protocol metadata for an HTTPS URL, or None."""
    host = host_of(url)
    if not host:
        return None
    port = port_of(url, 443) or 443
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert() or {}
                cipher = tls.cipher()
                return {
                    "protocol": tls.version(),
                    "cipher": cipher[0] if cipher else None,
                    "subject": _name_tuple(cert.get("subject")),
                    "issuer": _name_tuple(cert.get("issuer")),
                    "not_before": cert.get("notBefore"),
                    "not_after": cert.get("notAfter"),
                    "subject_alt_names": [
                        entry[1]
                        for entry in cert.get("subjectAltName", ())
                        if isinstance(entry, (tuple, list)) and len(entry) >= 2
                    ],
                    "expired": _is_expired(cert.get("notAfter")),
                    "provider": "native_tls",
                }
    except (ssl.SSLError, OSError, ValueError):
        return None


def _name_tuple(entries) -> list[list[str]]:
    """Flatten ``getpeercert()`` subject/issuer RDNs into ``[name, value]`` pairs.

    ``getpeercert()`` returns RDNs as nested groups: each group is a tuple of
    ``(oid, value)`` pairs, and a group holding a single attribute is a 1-tuple.
    Both levels are explicitly guarded instead of blindly indexed, so a
    malformed or empty subject/issuer degrades to ``[]`` rather than raising
    ``IndexError`` mid-probe.
    """
    out: list[list[str]] = []
    for group in (entries or []):
        if not isinstance(group, (tuple, list)):
            continue
        for pair in group:
            if isinstance(pair, (tuple, list)) and len(pair) >= 2:
                out.append([str(pair[0]), str(pair[1])])
    return out


def _is_expired(not_after: str | None) -> bool | None:
    if not not_after:
        return None
    try:
        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    return expiry < datetime.now(timezone.utc)


def technology_hints(headers: dict) -> list[dict]:
    """Extract stable technology hints from response headers."""
    hints: list[dict] = []
    lowered = {str(k).lower(): v for k, v in headers.items()}
    for header, label in _TECH_HINTS.items():
        if header in lowered and lowered[header]:
            hints.append({"header": header, "kind": label, "value": str(lowered[header])})
    return hints
