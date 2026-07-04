from __future__ import annotations

import re
import os
from functools import lru_cache
from typing import Any

from operations.core import (
    LAGOS_KEYWORDS,
    NIGERIA_KEYWORDS,
    THREAT_KEYWORDS,
    clean_text,
    detect_category,
    estimate_confidence,
    estimate_severity,
    geo_relevance_score,
    keyword_matches,
    quality_score,
    summarize,
)


ORG_TERMS = [
    "police",
    "nigeria police",
    "npf",
    "dss",
    "efcc",
    "lasema",
    "lastma",
    "lawma",
    "cbn",
    "inec",
    "lagos state government",
]

PERSON_PATTERN = re.compile(r"\b(?:Mr|Mrs|Ms|Dr|Prof|Hon|Chief|Inspector|Commissioner)\.?\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,2}\b")


@lru_cache(maxsize=1)
def _spacy_model() -> Any | None:
    if os.getenv("LEMTIK_ENABLE_SPACY", "1").strip().lower() in {"0", "false", "no"}:
        return None
    try:
        import spacy

        return spacy.load("en_core_web_sm")
    except Exception:
        return None


@lru_cache(maxsize=1)
def _sentiment_pipeline() -> Any | None:
    if os.getenv("LEMTIK_ENABLE_TRANSFORMERS", "0").strip().lower() not in {"1", "true", "yes"}:
        return None
    try:
        from transformers import pipeline

        return pipeline(
            "text-classification",
            model=os.getenv("LEMTIK_TRANSFORMERS_MODEL", "distilbert-base-uncased-finetuned-sst-2-english"),
            device=int(os.getenv("LEMTIK_TRANSFORMERS_DEVICE", "-1")),
        )
    except Exception:
        return None


def nlp_status() -> dict[str, Any]:
    return {
        "spacy_enabled": os.getenv("LEMTIK_ENABLE_SPACY", "1").strip().lower() not in {"0", "false", "no"},
        "spacy_loaded": _spacy_model() is not None,
        "transformers_enabled": os.getenv("LEMTIK_ENABLE_TRANSFORMERS", "0").strip().lower() in {"1", "true", "yes"},
        "transformers_loaded": _sentiment_pipeline() is not None,
        "active_entity_backend": "spacy:en_core_web_sm" if _spacy_model() is not None else "rule-based-fallback",
        "active_sentiment_backend": "transformers" if _sentiment_pipeline() is not None else "heuristic",
    }


def _unique(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        cleaned = clean_text(value).strip(" ,.;:-")
        key = cleaned.lower()
        if cleaned and key not in seen:
            seen.add(key)
            result.append(cleaned)
    return result


def _matched_terms(text: str, terms: list[str]) -> list[str]:
    lower_to_original = {term.lower(): term for term in terms}
    hits = keyword_matches(text, list(lower_to_original))
    return [lower_to_original[hit.lower()] for hit in hits]


def extract_entities(text: str) -> dict[str, list[str]]:
    cleaned = clean_text(text)
    model = _spacy_model()
    if model is not None:
        doc = model(cleaned[:5000])
        return {
            "locations": _unique([ent.text for ent in doc.ents if ent.label_ in {"GPE", "LOC", "FAC"}]),
            "organisations": _unique([ent.text for ent in doc.ents if ent.label_ == "ORG"]),
            "people": _unique([ent.text for ent in doc.ents if ent.label_ == "PERSON"]),
        }

    locations = _matched_terms(cleaned, LAGOS_KEYWORDS + NIGERIA_KEYWORDS)
    organisations = _matched_terms(cleaned, ORG_TERMS)
    people = PERSON_PATTERN.findall(cleaned)
    return {
        "locations": _unique(locations),
        "organisations": _unique(organisations),
        "people": _unique(people),
    }


def threat_score(text: str, severity: int, confidence: int, quality: int, hit_count: int) -> float:
    classifier = _sentiment_pipeline()
    if classifier is not None:
        try:
            result = classifier(clean_text(text)[:512])[0]
            if result["label"].upper() == "NEGATIVE":
                return round(float(result["score"]), 3)
            return round(1.0 - float(result["score"]), 3)
        except Exception:
            pass
    base = severity / 5
    confidence_weight = confidence / 100
    quality_weight = quality / 100
    keyword_weight = min(hit_count, 6) / 6
    score = (base * 0.45) + (confidence_weight * 0.25) + (quality_weight * 0.15) + (keyword_weight * 0.15)
    return round(max(0.0, min(score, 1.0)), 3)


def classify_text(
    text: str,
    *,
    credibility: str = "B",
    verified: str | None = None,
    custom_keywords: list[str] | None = None,
) -> dict[str, Any]:
    cleaned = clean_text(text)
    custom_keywords = custom_keywords or []
    category, category_hits = detect_category(cleaned)
    custom_hits = keyword_matches(cleaned, custom_keywords)
    geo_relevance = geo_relevance_score(cleaned, custom_keywords)
    item_quality = quality_score(cleaned)
    severity = estimate_severity(cleaned, credibility)
    verification = verified or ("Partial" if credibility == "A" else "No")
    confidence = estimate_confidence(credibility, verification, item_quality, len(category_hits) + len(custom_hits))
    entities = extract_entities(cleaned)
    all_hits = _unique(category_hits + custom_hits)
    return {
        "summary": summarize(cleaned),
        "threat_category": category,
        "severity": severity,
        "confidence": confidence,
        "quality_score": item_quality,
        "geo_relevance": geo_relevance,
        "matched_keywords": all_hits,
        "entities": entities,
        "threat_score": threat_score(cleaned, severity, confidence, item_quality, len(all_hits)),
        "collectable": item_quality >= 55 and geo_relevance != "None" and bool(all_hits),
        "model": nlp_status(),
    }


def classify_incident_payload(data: dict[str, Any]) -> dict[str, Any]:
    text = str(data.get("raw_content") or data.get("summary") or data.get("text") or "")
    custom_keywords = data.get("custom_keywords") or []
    if isinstance(custom_keywords, str):
        custom_keywords = [kw.strip() for kw in custom_keywords.split(",") if kw.strip()]
    classification = classify_text(
        text,
        credibility=str(data.get("credibility") or "B"),
        verified=data.get("verified"),
        custom_keywords=custom_keywords,
    )
    enriched = dict(data)
    enriched.update(
        {
            "summary": data.get("summary") or classification["summary"],
            "threat_category": data.get("threat_category") or classification["threat_category"],
            "severity": data.get("severity") or classification["severity"],
            "confidence": data.get("confidence") or classification["confidence"],
            "quality_score": data.get("quality_score") or classification["quality_score"],
            "geo_relevance": data.get("geo_relevance") or classification["geo_relevance"],
            "matched_keywords": data.get("matched_keywords") or ", ".join(classification["matched_keywords"]),
            "nlp": classification,
        }
    )
    return enriched
