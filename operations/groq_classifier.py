from __future__ import annotations

import json
import os
from typing import Any

try:
    import httpx
    from groq import Groq
except Exception:  # pragma: no cover - optional dependency until configured
    httpx = None  # type: ignore
    Groq = None  # type: ignore


# Deliberately NOT wired into the bulk RSS collection pipeline (collect_from_source in core.py) -
# that runs across every item on every source on every scheduled run (hundreds of articles/day),
# and the rule-based classifier (detect_category/estimate_severity/geo_relevance_score) already
# handles that volume for free with no rate-limit exposure. This is for the single-call paths:
# /classify and /brain/query's question interpretation - one request in, one classification out,
# where an LLM genuinely adds value the keyword list can't: nuance, and reading Pidgin/Yoruba/
# Hausa/Igbo text directly without a translation API, since Groq's models handle code-switched
# Nigerian English natively.
MODEL = os.getenv("OSINT_GROQ_MODEL", "openai/gpt-oss-20b")
MAX_COMPLETION_TOKENS = 600

_api_key = os.getenv("GROQ_API_KEY", "").strip()
_client: Any | None = None
_client_attempted = False

SYSTEM_PROMPT = (
    "You are a security intelligence classifier for a physical-security company operating in "
    "Lagos, Nigeria. Given a short news item or question (possibly in English, Nigerian Pidgin, "
    "Yoruba, Hausa, or Igbo, or a mix), return ONLY a JSON object with these exact keys: "
    '"threat_category" (one of "Physical", "Cyber", "Political", "Macro"), '
    '"severity" (integer 1-5, 5 being most severe/urgent), '
    '"confidence" (integer 0-100, your confidence in this classification), '
    '"summary" (one plain-English sentence, translated if the source text was not in English), '
    '"locations" (array of place names mentioned), '
    '"people" (array of person names mentioned), '
    '"organisations" (array of organisation names mentioned). '
    "No prose, no markdown, just the JSON object."
)


def _get_client() -> Any | None:
    global _client, _client_attempted
    if _client_attempted:
        return _client
    _client_attempted = True
    if Groq is None or not _api_key:
        return None
    try:
        # httpx defaults to HTTP/1.1 unless http2=True is passed explicitly - Cloudflare, which
        # fronts Groq's API, fingerprints HTTP/1.1-only requests as bot traffic and 403s them
        # even with a valid key (matches the exact issue masterai hit and fixed the same way).
        http_client = httpx.Client(http2=True) if httpx is not None else None
        _client = Groq(api_key=_api_key, http_client=http_client)
    except Exception:
        _client = None
    return _client


def groq_configured() -> bool:
    return _get_client() is not None


def classify_with_groq(text: str) -> dict[str, Any] | None:
    """Best-effort. Returns None on any failure (not configured, network error, malformed
    response) - callers must always have a deterministic fallback ready, never block on this."""
    client = _get_client()
    if client is None or not text.strip():
        return None
    try:
        response = client.chat.completions.create(
            model=MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": text[:4000]},
            ],
            temperature=0.2,
            max_tokens=MAX_COMPLETION_TOKENS,
            response_format={"type": "json_object"},
        )
        content = response.choices[0].message.content
        if not content or not content.strip():
            return None
        parsed = json.loads(content)
        return parsed if isinstance(parsed, dict) else None
    except Exception:
        return None
