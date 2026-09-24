"""Phase 12 static-asset observation from fetched HTML (real evidence only).

A ``script_asset`` observation is created only for a ``<script src>`` value that
was *actually present* in a fetched HTML document and resolves, through the
document's own URL, to an in-scope absolute URL.  Nothing is synthesized: a page
without script tags yields zero observations.
"""
from __future__ import annotations

from collections.abc import Callable
from html.parser import HTMLParser

from app.discovery.endpoints import KIND_SCRIPT_ASSET, SOURCE_HTML_SCRIPT, to_absolute


class _ScriptCollector(HTMLParser):
    """Collect only ``<script src="...">`` values from an HTML document."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.sources: list[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag.lower() != "script":
            return
        lowered = {k.lower(): v for k, v in attrs}
        value = (lowered.get("src") or "").strip()
        if value:
            self.sources.append(value)


def script_sources_from_html(html: str) -> list[str]:
    """Raw ``<script src>`` values observed in an HTML document."""
    if not html:
        return []
    collector = _ScriptCollector()
    try:
        collector.feed(html)
        collector.close()
    except Exception:  # pragma: no cover - defensive against malformed pages
        return []
    return collector.sources


def script_assets_from_documents(
    documents: list[dict],
    scope_guard: Callable[[str], bool],
    *,
    limit: int = 200,
) -> list[dict]:
    """Derive in-scope script-asset observations from fetched HTML documents.

    Each result has the shape ``{"url", "source", "base_url", "kind"}``.  A
    distinct URL appears once (deduplicated by absolute URL); out-of-scope and
    unresolved values are dropped -- they are never probed or reported here.
    """
    seen: set[str] = set()
    out: list[dict] = []
    for doc in documents:
        base_url = doc.get("url") or ""
        body = doc.get("body") or ""
        if not base_url or not body:
            continue
        for raw in script_sources_from_html(body):
            absolute = to_absolute(raw, base_url)
            if not absolute or not scope_guard(absolute):
                continue
            if absolute in seen:
                continue
            seen.add(absolute)
            out.append({
                "url": absolute,
                "source": SOURCE_HTML_SCRIPT,
                "base_url": base_url,
                "kind": KIND_SCRIPT_ASSET,
            })
            if len(out) >= limit:
                return out
    return out


__all__ = ["script_assets_from_documents", "script_sources_from_html"]