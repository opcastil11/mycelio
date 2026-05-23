"""Parse HTML into typed affordances for the FETCH verb.

Kinds emitted:
- ``link``: navigable URL (one ``<a href>``)
- ``form``: invokable form (one ``<form>``) — ``hints`` carries method + input fields

Relative hrefs are resolved against the page's final URL. Junk hrefs
(``javascript:``, ``mailto:``, ``#fragment-only``, empty) are dropped.
Output is capped at ``AFFORDANCE_LIMIT`` entries so a content-heavy page
doesn't blow up the response.
"""
from __future__ import annotations

from typing import Any
from urllib.parse import urljoin, urlparse

from lxml import html as lxml_html
from lxml.etree import ParserError

AFFORDANCE_LIMIT = 50
JUNK_SCHEMES = {"javascript", "mailto", "tel", "data", "blob"}


def parse_affordances(body: bytes, base_url: str) -> list[dict[str, Any]]:
    """Extract links + forms from HTML bytes. Returns a list of dicts
    keyed by ``kind``/``target``/``label``/(optional) ``hints``."""
    if not body:
        return []
    try:
        doc = lxml_html.fromstring(body)
    except (ValueError, ParserError):
        return []

    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    for a in doc.iter("a"):
        href = (a.get("href") or "").strip()
        if not href or href.startswith("#"):
            continue
        if urlparse(href).scheme.lower() in JUNK_SCHEMES:
            continue
        try:
            target = urljoin(base_url, href)
        except ValueError:
            continue
        label = (a.text_content() or "").strip()[:200] or target
        key = ("link", target)
        if key in seen:
            continue
        seen.add(key)
        out.append({"kind": "link", "target": target, "label": label})
        if len(out) >= AFFORDANCE_LIMIT:
            return out

    for form in doc.iter("form"):
        action = (form.get("action") or "").strip()
        method = (form.get("method") or "GET").upper()
        try:
            target = urljoin(base_url, action) if action else base_url
        except ValueError:
            continue
        fields: list[dict[str, Any]] = []
        for inp in form.iter("input"):
            name = inp.get("name")
            if not name:
                continue
            fields.append(
                {
                    "name": name,
                    "type": inp.get("type") or "text",
                    "required": inp.get("required") is not None,
                }
            )
        label = (
            form.get("aria-label")
            or form.get("name")
            or f"form: {method} {target}"
        )[:200]
        key = ("form", target)
        if key in seen:
            continue
        seen.add(key)
        out.append(
            {
                "kind": "form",
                "target": target,
                "label": label,
                "hints": {"method": method, "fields": fields},
            }
        )
        if len(out) >= AFFORDANCE_LIMIT:
            return out

    return out
