"""Section outline + section content from HTML.

Two extractors live here:

* :func:`structural_sections` walks ``<h1>`` to ``<h6>`` in document order
  and slices the DOM between consecutive headings. Free, ~1 ms per page.
* :func:`llm_sections` sends the already-extracted Markdown to Claude
  haiku and asks for a semantic section breakdown. Opt-in via env vars,
  meant for pages that don't use heading hierarchy properly (marketing
  SPAs, single-h1 landings).

Both return a uniform :class:`Section` list. The daemon's FETCH cache
holds them next to the full Markdown so subsequent ``outline_only`` and
``section_id`` requests cost zero upstream traffic.
"""
from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field

import httpx
from lxml import html as lxml_html
from lxml.etree import ParserError

log = logging.getLogger("mycd.outline")


SLUG_MAX_LEN = 60
PREVIEW_MAX_LEN = 120
ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_DEFAULT_MODEL = "claude-haiku-4-5-20251001"
LLM_MAX_CHARS = 24_000  # cap content sent to the LLM


@dataclass
class Section:
    """One section of a page. ``content`` is plain text; ``preview`` is the
    first ``PREVIEW_MAX_LEN`` characters with newlines collapsed."""

    id: str
    heading: str
    depth: int  # 1..6 for structural; 1..3 for LLM
    content: str
    preview: str = ""

    def __post_init__(self) -> None:
        if not self.preview and self.content:
            head = self.content[:PREVIEW_MAX_LEN].replace("\n", " ").strip()
            self.preview = head + ("…" if len(self.content) > PREVIEW_MAX_LEN else "")

    @property
    def size_bytes(self) -> int:
        return len(self.content.encode("utf-8"))


# ---------------------------------------------------------------------------
# Slugify
# ---------------------------------------------------------------------------


def _slugify(text: str) -> str:
    s = text.lower().strip()
    s = re.sub(r"[^a-z0-9\s-]", "", s)
    s = re.sub(r"[\s_-]+", "-", s).strip("-")
    return s[:SLUG_MAX_LEN] or "section"


def _unique_slug(base: str, used: dict[str, int]) -> str:
    slot = used.get(base, 0)
    used[base] = slot + 1
    return base if slot == 0 else f"{base}-{slot + 1}"


# ---------------------------------------------------------------------------
# Structural extractor
# ---------------------------------------------------------------------------


_HEADINGS = ("h1", "h2", "h3", "h4", "h5", "h6")


def structural_sections(body: bytes) -> list[Section]:
    """Walk ``<h1>``–``<h6>`` and slice the surrounding flow text into
    sections. Returns ``[]`` for pages with no real heading hierarchy."""
    if not body:
        return []
    try:
        doc = lxml_html.fromstring(body)
    except (ValueError, ParserError):
        return []

    headings = doc.xpath("//h1 | //h2 | //h3 | //h4 | //h5 | //h6")
    if not headings:
        return []

    sections: list[Section] = []
    used_ids: dict[str, int] = {}

    for idx, h in enumerate(headings):
        heading = (h.text_content() or "").strip()
        if not heading:
            continue
        depth = int(h.tag[1])
        sid = _unique_slug(_slugify(heading), used_ids)

        # Walk forward in document order until the next heading.
        # Skip non-element nodes (comments, processing instructions) — their
        # ``.tag`` isn't a string and ``.text_content()`` would raise.
        parts: list[str] = []
        node = h.getnext()
        while node is not None:
            if not isinstance(node.tag, str):
                node = node.getnext()
                continue
            if node.tag in _HEADINGS:
                break
            text = (node.text_content() or "").strip()
            if text:
                parts.append(text)
            node = node.getnext()

        # Also include any text inside parents after the heading, if the
        # heading is nested (e.g. inside <article>). Lightweight pass.
        if not parts:
            parent = h.getparent()
            if parent is not None:
                tail = (h.tail or "").strip()
                if tail:
                    parts.append(tail)

        content = "\n\n".join(parts).strip()
        sections.append(Section(id=sid, heading=heading, depth=depth, content=content))

    return sections


# ---------------------------------------------------------------------------
# LLM extractor (Claude haiku via Anthropic /v1/messages)
# ---------------------------------------------------------------------------


_LLM_SYSTEM_PROMPT = (
    "You split web page content into clean logical sections for an AI agent "
    "browsing the web. Output strict JSON only. No prose."
)

_LLM_USER_TEMPLATE = """Given this page content, return a JSON array of sections.
Each section is {{"id": "kebab-case-slug", "heading": "short title", "depth": 1-3, "preview": "first sentence"}}.

Rules:
- 3 to 8 sections. Group related paragraphs.
- depth 1 = major sections, depth 2 = sub-sections.
- id is kebab-case derived from heading.
- preview is the literal first sentence of that section's text.
- Do not invent content — only group what's already there.

Page content (may be truncated):
---
{content}
---

Return the JSON array only, no explanation."""


def llm_outline_enabled() -> bool:
    """True iff env is configured for the LLM outline path."""
    return (
        os.environ.get("MYCD_OUTLINE_LLM_PROVIDER", "").lower() == "anthropic"
        and bool(os.environ.get("ANTHROPIC_API_KEY"))
    )


async def llm_sections(
    markdown: str,
    *,
    http_client: httpx.AsyncClient,
    model: str | None = None,
) -> list[Section]:
    """Call Claude haiku to produce a semantic outline of ``markdown``.

    Returns ``Section`` objects whose ``content`` is empty — the LLM
    provides structure (id/heading/depth/preview), the daemon binds
    actual content by matching preview substrings against the full
    Markdown so an agent asking for a ``section_id`` gets real text.
    Raises :class:`LLMOutlineError` on failure; the caller decides
    whether to fall back to structural.
    """
    if not llm_outline_enabled():
        raise LLMOutlineError("llm outline not configured")
    if not markdown.strip():
        return []

    api_key = os.environ["ANTHROPIC_API_KEY"]
    model_id = model or os.environ.get("MYCD_OUTLINE_LLM_MODEL", ANTHROPIC_DEFAULT_MODEL)
    user_msg = _LLM_USER_TEMPLATE.format(content=markdown[:LLM_MAX_CHARS])

    try:
        r = await http_client.post(
            ANTHROPIC_API_URL,
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": model_id,
                "max_tokens": 2048,
                "system": _LLM_SYSTEM_PROMPT,
                "messages": [{"role": "user", "content": user_msg}],
            },
            timeout=30.0,
        )
    except httpx.HTTPError as exc:
        raise LLMOutlineError(f"anthropic call failed: {exc}") from exc
    if r.status_code >= 400:
        raise LLMOutlineError(f"anthropic returned HTTP {r.status_code}: {r.text[:200]}")

    try:
        body = r.json()
        text = body["content"][0]["text"]
    except (KeyError, IndexError, ValueError) as exc:
        raise LLMOutlineError(f"unexpected anthropic response: {exc}") from exc

    parsed = _parse_llm_json(text)
    sections: list[Section] = []
    used: dict[str, int] = {}
    for entry in parsed:
        if not isinstance(entry, dict):
            continue
        heading = str(entry.get("heading", "")).strip()
        if not heading:
            continue
        depth = max(1, min(3, int(entry.get("depth", 1) or 1)))
        preview = str(entry.get("preview", "")).strip()
        sid = _unique_slug(_slugify(str(entry.get("id") or heading)), used)
        sections.append(Section(id=sid, heading=heading, depth=depth, content="", preview=preview))
    return sections


def _parse_llm_json(text: str) -> list:
    """Tolerate code-fenced or trailing-comment JSON."""
    s = text.strip()
    # Strip a ```json ... ``` fence if present.
    fence = re.match(r"```(?:json)?\s*(.*?)\s*```", s, re.DOTALL)
    if fence:
        s = fence.group(1).strip()
    # Find first '[' and last ']' as a defensive trim.
    start = s.find("[")
    end = s.rfind("]")
    if start != -1 and end != -1 and end > start:
        s = s[start : end + 1]
    try:
        return json.loads(s)
    except json.JSONDecodeError as exc:
        raise LLMOutlineError(f"could not parse llm json: {exc}") from exc


def bind_llm_content(sections: list[Section], full_markdown: str) -> list[Section]:
    """Best-effort: match each LLM section's ``preview`` substring against
    ``full_markdown`` to determine boundaries, then slice in order.

    If matching fails for any section, that section's content stays empty
    and the agent only sees the heading/preview — still useful for the
    outline view, but ``section_id`` retrieval will return an empty body.
    """
    if not sections:
        return []
    positions: list[int] = []
    cursor = 0
    for s in sections:
        marker = s.preview[:40] if s.preview else s.heading[:40]
        pos = full_markdown.find(marker, cursor) if marker else -1
        if pos == -1 and marker:
            # Try a fuzzy-ish retry: case-insensitive, anywhere after cursor.
            lower = full_markdown.lower()
            pos = lower.find(marker.lower(), cursor)
        positions.append(pos)
        if pos != -1:
            cursor = pos + 1

    for i, s in enumerate(sections):
        start = positions[i]
        if start == -1:
            continue
        end = len(full_markdown)
        for j in range(i + 1, len(positions)):
            if positions[j] != -1:
                end = positions[j]
                break
        s.content = full_markdown[start:end].strip()
        # Refresh preview if it was empty.
        if not s.preview and s.content:
            head = s.content[:PREVIEW_MAX_LEN].replace("\n", " ").strip()
            s.preview = head + ("…" if len(s.content) > PREVIEW_MAX_LEN else "")
    return sections


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class LLMOutlineError(Exception):
    """Raised when the LLM outline path fails (network, parse, config)."""


# ---------------------------------------------------------------------------
# Lookup helpers
# ---------------------------------------------------------------------------


def find_section(sections: list[Section], section_id: str) -> Section | None:
    for s in sections:
        if s.id == section_id:
            return s
    return None
