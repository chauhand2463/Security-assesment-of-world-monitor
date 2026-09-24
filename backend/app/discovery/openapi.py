"""Phase 12 OpenAPI document observation (real evidence only).

An observed OpenAPI document is itself a fetched fact.  The endpoints and
parameters it *declares* are surfaced as ``api_endpoint_candidate`` /
``api_parameter_candidate`` observations -- the document is the evidence, so
"NO OBSERVATION -> NO HYPOTHESIS EXECUTION -> NO FINDING" still holds (these are
surface facts, never vulnerability findings).

Deliberately dependency-free: only JSON documents are parsed.  A YAML document
that happens to be served at a probe path is still recorded as an observed
``api_document`` with an honest ``unsupported`` parse status rather than being
guessed at.  Every resolved endpoint passes the authorized scope guard.
"""
from __future__ import annotations

import json
from collections.abc import Callable
from urllib.parse import urlsplit

from app.discovery.endpoints import KIND_API_ENDPOINT, KIND_API_PARAMETER, SOURCE_OPENAPI

_METHODS = ("get", "post", "put", "patch", "delete", "head", "options")

_MAX_ENDPOINTS = 200
_MAX_PARAMETERS = 400


def _origin_of(url: str) -> str | None:
    """Strict ``scheme://host[:port]`` origin; None when unparseable."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
        return None
    netloc = parts.netloc
    return f"{parts.scheme.lower()}://{netloc}"


def _server_base(data: dict, source_url: str, scope_guard: Callable[[str], bool]) -> str | None:
    """Resolve the declared base URL for paths: ``servers[0]`` when present and
    in scope, else the document's own origin.  Never a guess: ``servers`` is an
    observed declaration in the document itself."""
    declared = data.get("servers")
    if isinstance(declared, list):
        for server in declared:
            if not isinstance(server, dict):
                continue
            raw = str(server.get("url") or "").strip().rstrip("/")
            if raw and scope_guard(raw):
                return raw
    return _origin_of(source_url)


def _methods_of(item: dict) -> list[str]:
    return [m for m in _METHODS if isinstance(item.get(m), dict)]


def parse_openapi(
    body: str,
    source_url: str,
    scope_guard: Callable[[str], bool],
    *,
    max_endpoints: int = _MAX_ENDPOINTS,
    max_parameters: int = _MAX_PARAMETERS,
) -> dict:
    """Parse one OpenAPI (JSON) document body into observed surface facts.

    Returns ``{"parsed": bool, "reason": str, "base": str|None,
    "endpoints": [...], "parameters": [...]}``.  ``parsed`` is False when the
    body is not valid JSON with a ``paths`` section (a YAML or non-OpenAPI
    response is recorded, not guessed at).
    """
    if not body:
        return {"parsed": False, "reason": "empty document body",
                "base": None, "endpoints": [], "parameters": []}
    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        return {"parsed": False,
                "reason": "not a JSON document (YAML OpenAPI is not parsed)",
                "base": None, "endpoints": [], "parameters": []}
    if not isinstance(data, dict) or not isinstance(data.get("paths"), dict):
        return {"parsed": False, "reason": "no 'paths' section in document",
                "base": None, "endpoints": [], "parameters": []}

    base = _server_base(data, source_url, scope_guard)
    if not base:
        return {"parsed": False, "reason": "document base URL refused by scope guard",
                "base": None, "endpoints": [], "parameters": []}

    endpoints: list[dict] = []
    parameters: list[dict] = []
    seen_endpoints: set[tuple[str, str]] = set()
    seen_parameters: set[tuple[str, str, str]] = set()

    def _add_endpoint(method: str, url: str) -> None:
        key = (method.upper(), url)
        if key in seen_endpoints:
            return
        seen_endpoints.add(key)
        endpoints.append({
            "url": url,
            "method": method.upper(),
            "source": SOURCE_OPENAPI,
            "source_url": source_url,
        })

    def _add_parameter(url: str, name: str, location: str, required: bool) -> None:
        name = (name or "").strip()
        if not name:
            return
        norm = (url, name, location or "query")
        if norm in seen_parameters:
            return
        seen_parameters.add(norm)
        parameters.append({
            "url": url,
            "parameter": name,
            "location": location or "query",
            "required": bool(required),
            "source": SOURCE_OPENAPI,
            "source_url": source_url,
        })

    for path, item in data["paths"].items():
        path = path if isinstance(path, str) else ""
        if not path or not path.startswith("/"):
            continue
        url = f"{base}{path}"
        if not scope_guard(url):
            continue
        if not isinstance(item, dict):
            continue

        path_params = item.get("parameters")
        if isinstance(path_params, list):
            for p in path_params:
                if not isinstance(p, dict) or not isinstance(p.get("name"), str):
                    continue
                _add_parameter(url, p.get("name", ""), str(p.get("in") or "query"),
                               bool(p.get("required")))

        for method in _methods_of(item):
            _add_endpoint(method, url)
            params = item[method].get("parameters")
            if isinstance(params, list):
                for p in params:
                    if not isinstance(p, dict) or not isinstance(p.get("name"), str):
                        continue
                    _add_parameter(url, p.get("name", ""), str(p.get("in") or "query"),
                                   bool(p.get("required")))
            if len(endpoints) >= max_endpoints:
                return {"parsed": True, "reason": "ok (limit reached)",
                        "base": base, "endpoints": endpoints, "parameters": parameters}
            if len(parameters) >= max_parameters:
                return {"parsed": True, "reason": "ok (parameter limit reached)",
                        "base": base, "endpoints": endpoints, "parameters": parameters}

    return {"parsed": True, "reason": "ok", "base": base,
            "endpoints": endpoints, "parameters": parameters}


__all__ = ["parse_openapi", "KIND_API_ENDPOINT", "KIND_API_PARAMETER", "SOURCE_OPENAPI"]