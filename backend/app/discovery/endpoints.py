"""Phase 11 endpoint & parameter discovery (native, real evidence only).

Slice 1 of the Phase 11 discovery intelligence.  Candidate endpoints and query
parameters are deduced exclusively from *real fetched content* -- robots.txt,
sitemap.xml and root HTML links.  This module never synthesizes a candidate:
an empty or failed fetch yields zero candidates, and any URL outside the
authorized scope is refused before it is returned.

A discovery candidate is a *hypothesis* about the attack surface, NOT a
vulnerability finding.  Per the Phase 11 boundary, findings may only be created
from verified evidence; this module only ever reports what the observed content
contained.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import parse_qs, urljoin, urlsplit
from collections.abc import Callable

# Canonical discovery sources (why a candidate is believed to exist).
SOURCE_ROBOTS = "robots"
SOURCE_ROBOTS_SITEMAP = "robots.sitemap"
SOURCE_SITEMAP = "sitemap"
SOURCE_HTML = "html"
SOURCE_HTML_SCRIPT = "html_script"  # a <script src> observable in fetched HTML
SOURCE_OPENAPI = "openapi"  # an endpoint/parameter declared by an observed OpenAPI doc

# Observation kinds emitted by the endpoint discovery engine.
KIND_CANDIDATE = "endpoint_candidate"
KIND_PARAMETER = "parameter_candidate"
KIND_OUT_OF_SCOPE = "endpoint_out_of_scope"
KIND_SUMMARY = "endpoint_discovery"
# Phase 12 additive kinds: static assets and API documents observed on the
# surface (plus the endpoints/parameters an observed OpenAPI document declares).
KIND_SCRIPT_ASSET = "script_asset"
KIND_API_DOCUMENT = "api_document"
KIND_API_ENDPOINT = "api_endpoint_candidate"
KIND_API_PARAMETER = "api_parameter_candidate"

# URLs this module may probe for a machine-readable OpenAPI document, in
# preference order (bounded, well-known advertised locations; probing stops at
# the first document that parses).  This is a documented discovery act, not an
# arbitrary-method brute force: every candidate is fetched as GET only.
OPENAPI_CANDIDATE_PATHS = (
    "/openapi.json",
    "/api-docs",
    "/swagger/v1/swagger.json",
    "/openapi.yaml",
    "/api/openapi.json",
)

_PROBE_FAIL_STATES = ("error", "unreachable", "skipped")

_HTML_LINK_TAGS = {
    "a": ("href",),
    "area": ("href",),
    "form": ("action",),
    "link": ("href",),
    "script": ("src",),
    "img": ("src",),
    "iframe": ("src",),
    "source": ("src",),
}

_SKIP_PREFIXES = ("#", "javascript:", "data:", "mailto:", "tel:", "blob:", "about:")


class _LinkCollector(HTMLParser):
    """Collect href/src/form-action values from an HTML document."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.values: list[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        wanted = _HTML_LINK_TAGS.get(tag)
        if not wanted:
            return
        lowered = {k.lower(): v for k, v in attrs}
        for attr in wanted:
            value = (lowered.get(attr) or "").strip()
            if value:
                self.values.append(value)


def to_absolute(raw: str | None, base_url: str) -> str | None:
    """Resolve a raw URL value against ``base_url``; None when not probeable.

    Only ``http(s)`` absolute URLs survive; internal/library schemes and
    URLs carrying embedded credentials are refused (the HTTP client would not
    probe them either).
    """
    if not raw:
        return None
    value = raw.strip()
    if not value or value.lower().startswith(_SKIP_PREFIXES):
        return None
    try:
        absolute = urljoin(base_url, value)
    except ValueError:
        return None
    parsed = urlsplit(absolute)
    if parsed.scheme.lower() not in ("http", "https"):
        return None
    if parsed.username or parsed.password:
        return None
    if parsed.fragment:
        absolute = absolute.split("#", 1)[0]
    return absolute


def endpoint_key(url: str) -> tuple[str, str, str]:
    """Stable identity for an endpoint: (scheme, host, path), query ignored."""
    p = urlsplit(url)
    return (p.scheme.lower(), (p.hostname or "").lower(), p.path or "/")


def without_query(url: str) -> str:
    """Return the URL with any query string removed (fragments already gone)."""
    return urlsplit(url)._replace(query="").geturl()


def query_parameters(url: str) -> list[str]:
    """Observed query parameter names on a URL, sorted and deduplicated."""
    query = urlsplit(url).query
    if not query:
        return []
    return sorted({k for k in parse_qs(query)})


def links_from_html(html: str) -> list[str]:
    """Raw href/src/form-action values observed in an HTML document."""
    if not html:
        return []
    collector = _LinkCollector()
    try:
        collector.feed(html)
        collector.close()
    except Exception:  # pragma: no cover - defensive against malformed pages
        return []
    return collector.values


def parse_robots(text: str) -> dict:
    """Parse robots.txt into ``{"disallow": [paths], "sitemaps": [urls]}``.

    ``Disallow`` and ``Sitemap`` lines are honored wherever they appear in the
    file (attack-surface discovery cares about every stated path, regardless of
    which user-agent block they belong to).  ``Allow`` lines are deliberately
    not turned into candidates: they do not declare an endpoint, they exempt
    one from crawl use.
    """
    disallow: list[str] = []
    sitemaps: list[str] = []
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        lowered = line.lower()
        if lowered.startswith("http/"):
            continue
        if lowered.startswith("disallow:"):
            path = line.split(":", 1)[1].strip()
            if path:
                disallow.append(path)
        elif lowered.startswith("sitemap:"):
            url = line.split(":", 1)[1].strip()
            if url:
                sitemaps.append(url)
    return {"disallow": disallow, "sitemaps": sitemaps}


def parse_sitemap(xml: str) -> list[str]:
    """All ``<loc>`` URLs from a sitemap or sitemap index document."""
    if not xml:
        return []
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return []
    locs: list[str] = []
    for elem in root.iter():
        if elem.tag.rsplit("}", 1)[-1].lower() == "loc" and elem.text and elem.text.strip():
            locs.append(elem.text.strip())
    return locs


def classify_document(url: str, body: str, content_type: str | None = None) -> str | None:
    """Classify a fetched body as robots/sitemap/html where it can be trusted."""
    if not url or not body:
        return None
    path = urlsplit(url).path.lower()
    ctype = (content_type or "").lower()
    if "text/plain" in ctype or "text/html" in ctype:
        pass
    if path.endswith("/robots.txt") or path.endswith("robots.txt"):
        return SOURCE_ROBOTS
    if path.endswith(".xml") or "xml" in ctype:
        return SOURCE_SITEMAP
    if "text/html" in ctype:
        return SOURCE_HTML
    stripped = body.lstrip()[:80].lower()
    if stripped.startswith(("<!doctype", "<html", "<title", "<head", "<body")):
        return SOURCE_HTML
    if stripped.startswith("<?xml") or "<loc>" in body:
        return SOURCE_SITEMAP
    return None


@dataclass
class DiscoveryReport:
    """Everything the endpoint discovery engine observed in given documents."""

    endpoints: list[dict] = field(default_factory=list)  # url, key, source, base_url, method
    parameters: list[dict] = field(default_factory=list)  # url, parameter, source
    sources: dict[str, int] = field(default_factory=dict)  # source -> candidate count
    refused: list[str] = field(default_factory=list)  # observed but out-of-scope URLs
    notes: list[str] = field(default_factory=list)

    @property
    def candidate_count(self) -> int:
        return len(self.endpoints)

    @property
    def parameter_count(self) -> int:
        return len(self.parameters)


def discover_from_documents(
    documents: list[dict],
    scope_guard: Callable[[str], bool],
) -> DiscoveryReport:
    """Derive endpoint/parameter candidates from *real fetched documents*.

    ``documents`` entries have the shape ``{"url", "body", "content_type"}``.
    Candidates are deduplicated by ``endpoint_key`` (query agnostic); observed
    query parameters are collected across every variant of an endpoint.
    ``scope_guard(url)`` decides authorization -- anything it refuses is
    recorded as refused, never returned as a candidate.
    """
    report = DiscoveryReport()
    seen: set[tuple[str, str, str]] = set()
    params: dict[tuple[str, str], dict] = {}

    def _emit(url_value: str, source: str, base_url: str) -> None:
        absolute = to_absolute(url_value, base_url)
        if not absolute:
            return
        if not scope_guard(absolute):
            report.refused.append(absolute)
            return
        key = endpoint_key(absolute)
        endpoint_url = without_query(absolute)
        report.sources[source] = report.sources.get(source, 0) + 1
        if key not in seen:
            seen.add(key)
            report.endpoints.append({
                "url": endpoint_url,
                "key": key,
                "source": source,
                "base_url": base_url,
                "method": None,  # observed URL only; method is never inferred
            })
        for parameter in query_parameters(absolute):
            params[(endpoint_url, parameter)] = {
                "url": endpoint_url,
                "parameter": parameter,
                "source": source,
            }

    for doc in documents:
        base_url = doc.get("url") or ""
        kind = classify_document(base_url, doc.get("body") or "", doc.get("content_type"))
        if kind is None:
            continue
        if kind == SOURCE_ROBOTS:
            parsed = parse_robots(doc.get("body") or "")
            for path in parsed["disallow"]:
                _emit(path, kind, base_url)
            for sitemap_url in parsed["sitemaps"]:
                _emit(sitemap_url, SOURCE_ROBOTS_SITEMAP, base_url)
        elif kind == SOURCE_SITEMAP:
            for loc in parse_sitemap(doc.get("body") or ""):
                _emit(loc, kind, base_url)
        elif kind == SOURCE_HTML:
            for raw in links_from_html(doc.get("body") or ""):
                _emit(raw, kind, base_url)

    report.parameters = sorted(
        (v for v in params.values()),
        key=lambda v: (v["url"], v["parameter"]),
    )
    return report


__all__ = [
    "SOURCE_ROBOTS", "SOURCE_ROBOTS_SITEMAP", "SOURCE_SITEMAP", "SOURCE_HTML",
    "SOURCE_HTML_SCRIPT", "SOURCE_OPENAPI",
    "KIND_CANDIDATE", "KIND_PARAMETER", "KIND_OUT_OF_SCOPE", "KIND_SUMMARY",
    "KIND_SCRIPT_ASSET", "KIND_API_DOCUMENT", "KIND_API_ENDPOINT",
    "KIND_API_PARAMETER", "OPENAPI_CANDIDATE_PATHS",
    "DiscoveryReport", "classify_document", "discover_from_documents",
    "endpoint_key", "links_from_html", "parse_robots", "parse_sitemap",
    "query_parameters", "to_absolute", "without_query",
]