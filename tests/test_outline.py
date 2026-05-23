"""Tests for the outline extractors (structural + LLM)."""
from __future__ import annotations

import os

import httpx
import pytest

from mycd.outline import (
    LLMOutlineError,
    Section,
    _slugify,
    bind_llm_content,
    find_section,
    llm_outline_enabled,
    llm_sections,
    structural_sections,
)


# ---------------------------------------------------------------------------
# Structural
# ---------------------------------------------------------------------------

DOCS_HTML = b"""<!DOCTYPE html><html><body>
<article>
<h1>Stripe Docs</h1>
<p>Welcome to the docs.</p>
<h2>Auth</h2>
<p>Use a bearer token in the Authorization header.</p>
<p>Tokens start with sk_ for secret keys.</p>
<h2>Charges</h2>
<p>Create a charge with POST /v1/charges.</p>
<h3>Webhooks</h3>
<p>Subscribe to events via webhook endpoints.</p>
<h2>Charges</h2>
<p>Second heading with the same name on purpose.</p>
</article>
</body></html>"""


def test_structural_extracts_sections_in_order():
    secs = structural_sections(DOCS_HTML)
    ids = [s.id for s in secs]
    assert ids == ["stripe-docs", "auth", "charges", "webhooks", "charges-2"]


def test_structural_preserves_depth():
    secs = structural_sections(DOCS_HTML)
    depths = {s.id: s.depth for s in secs}
    assert depths == {
        "stripe-docs": 1,
        "auth": 2,
        "charges": 2,
        "webhooks": 3,
        "charges-2": 2,
    }


def test_structural_section_content_and_preview():
    secs = structural_sections(DOCS_HTML)
    auth = next(s for s in secs if s.id == "auth")
    assert "Authorization header" in auth.content
    assert "Tokens start with sk_" in auth.content
    assert auth.preview.startswith("Use a bearer token")


def test_structural_returns_empty_for_no_headings():
    assert structural_sections(b"<html><body><p>just text</p></body></html>") == []
    assert structural_sections(b"") == []


def test_structural_handles_garbage_input():
    # lxml is lenient; even invalid html shouldn't crash.
    assert structural_sections(b"<this is not html") in ([], [])  # tolerant


def test_structural_skips_comment_nodes_between_headings():
    """Regression: HTML comments between siblings used to crash
    ``node.text_content()`` because Comment nodes aren't elements."""
    html = b"""<html><body>
<h1>Top</h1>
<p>intro text</p>
<!-- this comment used to blow us up -->
<p>more text</p>
<h2>Next</h2>
<p>section two</p>
</body></html>"""
    secs = structural_sections(html)
    ids = [s.id for s in secs]
    assert ids == ["top", "next"]
    assert "intro text" in secs[0].content
    assert "more text" in secs[0].content


def test_slugify_basics():
    assert _slugify("Hello World") == "hello-world"
    assert _slugify("  Mixed -- Case 42!! ") == "mixed-case-42"
    assert _slugify("") == "section"


def test_find_section():
    secs = structural_sections(DOCS_HTML)
    assert find_section(secs, "auth").heading == "Auth"
    assert find_section(secs, "nope") is None


# ---------------------------------------------------------------------------
# LLM
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_env():
    saved = {k: os.environ.get(k) for k in
             ("MYCD_OUTLINE_LLM_PROVIDER", "ANTHROPIC_API_KEY", "MYCD_OUTLINE_LLM_MODEL")}
    yield
    for k, v in saved.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v


def test_llm_outline_disabled_by_default():
    os.environ.pop("MYCD_OUTLINE_LLM_PROVIDER", None)
    os.environ.pop("ANTHROPIC_API_KEY", None)
    assert llm_outline_enabled() is False


def test_llm_outline_enabled_requires_both():
    os.environ["MYCD_OUTLINE_LLM_PROVIDER"] = "anthropic"
    os.environ.pop("ANTHROPIC_API_KEY", None)
    assert llm_outline_enabled() is False
    os.environ["ANTHROPIC_API_KEY"] = "sk-test"
    assert llm_outline_enabled() is True


def _mock_anthropic(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


@pytest.mark.asyncio
async def test_llm_sections_happy_path():
    os.environ["MYCD_OUTLINE_LLM_PROVIDER"] = "anthropic"
    os.environ["ANTHROPIC_API_KEY"] = "sk-test"

    def handler(request):
        assert request.url.path == "/v1/messages"
        return httpx.Response(200, json={
            "content": [{
                "type": "text",
                "text": '[{"id":"intro","heading":"Intro","depth":1,"preview":"Welcome to the docs"},'
                        '{"id":"auth","heading":"Auth","depth":2,"preview":"Use a bearer token"}]'
            }]
        })

    async with _mock_anthropic(handler) as cli:
        secs = await llm_sections("Welcome to the docs. Use a bearer token.", http_client=cli)
        assert [s.id for s in secs] == ["intro", "auth"]
        assert secs[1].heading == "Auth"
        assert secs[1].depth == 2


@pytest.mark.asyncio
async def test_llm_sections_tolerates_fenced_json():
    os.environ["MYCD_OUTLINE_LLM_PROVIDER"] = "anthropic"
    os.environ["ANTHROPIC_API_KEY"] = "sk-test"

    def handler(request):
        return httpx.Response(200, json={
            "content": [{
                "type": "text",
                "text": '```json\n[{"id":"a","heading":"A","depth":1,"preview":"x"}]\n```'
            }]
        })

    async with _mock_anthropic(handler) as cli:
        secs = await llm_sections("x", http_client=cli)
        assert len(secs) == 1
        assert secs[0].id == "a"


@pytest.mark.asyncio
async def test_llm_sections_raises_on_http_error():
    os.environ["MYCD_OUTLINE_LLM_PROVIDER"] = "anthropic"
    os.environ["ANTHROPIC_API_KEY"] = "sk-test"

    def handler(request):
        return httpx.Response(500, text="boom")

    async with _mock_anthropic(handler) as cli:
        with pytest.raises(LLMOutlineError, match="500"):
            await llm_sections("x", http_client=cli)


@pytest.mark.asyncio
async def test_llm_sections_raises_when_disabled():
    os.environ.pop("MYCD_OUTLINE_LLM_PROVIDER", None)

    def handler(request):
        return httpx.Response(200)

    async with _mock_anthropic(handler) as cli:
        with pytest.raises(LLMOutlineError, match="not configured"):
            await llm_sections("x", http_client=cli)


def test_bind_llm_content_matches_previews():
    secs = [
        Section(id="a", heading="A", depth=1, content="", preview="first chunk"),
        Section(id="b", heading="B", depth=1, content="", preview="second chunk"),
    ]
    md = "intro\n\nfirst chunk here is the body of A\n\nsecond chunk and this is B"
    out = bind_llm_content(secs, md)
    assert "first chunk here" in out[0].content
    assert "second chunk and this is B" in out[1].content


def test_bind_llm_content_handles_unmatched_preview():
    secs = [
        Section(id="a", heading="A", depth=1, content="", preview="does not appear"),
        Section(id="b", heading="B", depth=1, content="", preview="this does"),
    ]
    md = "this does appear at the end"
    out = bind_llm_content(secs, md)
    assert out[0].content == ""  # unmatched, empty content
    assert "this does appear" in out[1].content
