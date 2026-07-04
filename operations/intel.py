from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from operations.analytics import risk_rating, since_iso
from operations.core import clean_text, row_to_dict, rows
from operations.nlp import classify_text, extract_entities


TASK_HINTS = {
    "physical": ["inventory:officers_nearby", "inventory:vehicles_available", "routing:fastest_route"],
    "robbery": ["inventory:officers_nearby", "inventory:vehicles_available", "routing:fastest_route"],
    "kidnapping": ["inventory:officers_nearby", "inventory:vehicles_available", "routing:fastest_route", "surveillance:area_cctv"],
    "clash": ["inventory:officers_nearby", "routing:fastest_route", "surveillance:area_cctv"],
    "protest": ["inventory:officers_nearby", "routing:traffic_disruption", "surveillance:area_cctv"],
    "traffic": ["routing:traffic_lights", "routing:fastest_route", "surveillance:area_cctv"],
    "fire": ["inventory:fire_units", "routing:fastest_route"],
    "flood": ["routing:fastest_route", "inventory:boats_or_high_clearance"],
}


def _tokens(value: str) -> list[str]:
    return [token for token in re.findall(r"[a-z0-9]+", clean_text(value).lower()) if len(token) > 1]


def _location_terms(location: str, entities: dict[str, list[str]]) -> list[str]:
    terms = _tokens(location)
    for entity in entities.get("locations", []):
        terms.extend(_tokens(entity))
    return sorted({term for term in terms if term})


def _score_incident(summary: str, location_terms: list[str], text_terms: list[str], incident: dict[str, Any]) -> int:
    haystack = " ".join(
        [
            str(incident.get("summary", "")),
            str(incident.get("location_relevance", "")),
            str(incident.get("geo_relevance", "")),
            str(incident.get("source", "")),
        ]
    ).lower()
    score = 0
    if any(term in haystack for term in location_terms):
        score += 3
    if any(term in haystack for term in text_terms):
        score += 2
    if str(incident.get("threat_category", "")).lower() in summary.lower():
        score += 1
    score += min(int(incident.get("severity") or 1), 5)
    return score


def _recent_incidents(org_id: str, days: int, limit: int = 300) -> list[dict[str, Any]]:
    return [
        row_to_dict(row)
        for row in rows(
            """
            select id, log_id, collected_at, source, source_url, summary, threat_category,
                   severity, location_relevance, geo_relevance, verified, status, confidence,
                   quality_score, matched_keywords
            from incidents
            where org_id = ?
            and collected_at >= ?
            and status != 'Archived'
            order by collected_at desc
            limit ?
            """,
            (org_id, since_iso(days), limit),
        )
    ]


def _area_history(org_id: str, location_terms: list[str], days: int) -> dict[str, Any]:
    incidents = _recent_incidents(org_id, days, 400)
    matched = [incident for incident in incidents if any(term in " ".join(
        [
            str(incident.get("summary", "")),
            str(incident.get("location_relevance", "")),
            str(incident.get("geo_relevance", "")),
            str(incident.get("source", "")),
        ]
    ).lower() for term in location_terms)]
    severity_counts = {
        "1": sum(1 for item in matched if int(item.get("severity") or 1) == 1),
        "2": sum(1 for item in matched if int(item.get("severity") or 1) == 2),
        "3": sum(1 for item in matched if int(item.get("severity") or 1) == 3),
        "4": sum(1 for item in matched if int(item.get("severity") or 1) == 4),
        "5": sum(1 for item in matched if int(item.get("severity") or 1) == 5),
    }
    high = sum(1 for item in matched if int(item.get("severity") or 1) >= 4)
    max_sev = max([int(item.get("severity") or 1) for item in matched], default=0)
    avg_conf = round(sum(float(item.get("confidence") or 0) for item in matched) / len(matched), 2) if matched else 0.0
    return {
        "days": days,
        "matched_count": len(matched),
        "high_severity_count": high,
        "max_severity": max_sev,
        "avg_confidence": avg_conf,
        "severity_counts": severity_counts,
        "risk_rating": risk_rating(max_sev, high, len(matched)),
    }


def _similar_incidents(org_id: str, location_terms: list[str], text_terms: list[str], days: int, limit: int) -> list[dict[str, Any]]:
    incidents = _recent_incidents(org_id, days, 400)
    ranked = sorted(
        (
            (
                _score_incident(" ".join(text_terms), location_terms, text_terms, incident),
                incident,
            )
            for incident in incidents
        ),
        key=lambda item: (item[0], item[1].get("collected_at", "")),
        reverse=True,
    )
    return [incident for score, incident in ranked[:limit] if score > 0]


def _routing_hints(classification: dict[str, Any], location_terms: list[str], similar: list[dict[str, Any]]) -> list[str]:
    hints: list[str] = []
    category = str(classification.get("threat_category") or "").lower()
    severity = int(classification.get("severity") or 1)
    for key, value in TASK_HINTS.items():
        if key in category:
            hints.extend(value)
    if severity >= 4:
        hints.extend(["relationship_api:dispatch_required", "relationship_api:escalate_review"])
    if location_terms:
        hints.extend(["osint:heatmap_lookup", "osint:similar_incident_lookup"])
    if similar and any(int(item.get("severity") or 1) >= 4 for item in similar):
        hints.append("relationship_api:historical_pattern_match")
    return sorted({hint for hint in hints})


def _queries_needed(classification: dict[str, Any]) -> list[str]:
    queries = ["incident_context", "location_history", "similar_incidents"]
    severity = int(classification.get("severity") or 1)
    category = str(classification.get("threat_category") or "").lower()
    if severity >= 4:
        queries.extend(["nearest_units", "available_vehicles", "route_optimization"])
    if any(term in category for term in ["physical", "robbery", "kidnap", "clash"]):
        queries.extend(["weapon_inventory", "officer_proximity"])
    if any(term in category for term in ["traffic", "road", "vehicle"]):
        queries.extend(["traffic_state", "smart_gates", "traffic_lights"])
    return sorted({query for query in queries})


def _graph_payload(packet_id: str, classification: dict[str, Any], location_terms: list[str], similar: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    nodes: list[dict[str, Any]] = [
        {"id": f"incident:{packet_id}", "label": "Incident", "type": "incident"},
    ]
    edges: list[dict[str, Any]] = []
    category = str(classification.get("threat_category") or "Unknown")
    category_node = f"category:{category.lower()}"
    nodes.append({"id": category_node, "label": category, "type": "category"})
    edges.append({"from": f"incident:{packet_id}", "to": category_node, "type": "CLASSIFIED_AS"})

    for term in location_terms[:8]:
        node_id = f"location:{term}"
        nodes.append({"id": node_id, "label": term, "type": "location"})
        edges.append({"from": f"incident:{packet_id}", "to": node_id, "type": "MENTIONS"})

    for incident in similar[:10]:
        node_id = f"incident:{incident.get('log_id') or incident.get('id')}"
        nodes.append(
            {
                "id": node_id,
                "label": incident.get("log_id") or str(incident.get("id")),
                "type": "incident",
                "severity": incident.get("severity"),
                "summary": incident.get("summary"),
            }
        )
        edges.append({"from": f"incident:{packet_id}", "to": node_id, "type": "SIMILAR_TO"})

    unique_nodes = []
    seen_nodes = set()
    for node in nodes:
        if node["id"] in seen_nodes:
            continue
        seen_nodes.add(node["id"])
        unique_nodes.append(node)
    unique_edges = []
    seen_edges = set()
    for edge in edges:
        key = (edge["from"], edge["to"], edge["type"])
        if key in seen_edges:
            continue
        seen_edges.add(key)
        unique_edges.append(edge)
    return {"nodes": unique_nodes, "edges": unique_edges}


def intelligence_packet(
    *,
    org_id: str,
    incident_text: str,
    location: str = "",
    lookback_days: int = 180,
    recent_limit: int = 10,
    custom_keywords: list[str] | None = None,
    task: str = "incident_assessment",
) -> dict[str, Any]:
    custom_keywords = custom_keywords or []
    classification = classify_text(
        incident_text,
        custom_keywords=custom_keywords,
    )
    entities = classification.get("entities") or extract_entities(incident_text)
    location_terms = _location_terms(location, entities)
    text_terms = _tokens(incident_text) + [term for term in _tokens(location)]
    similar = _similar_incidents(org_id, location_terms, text_terms, lookback_days, recent_limit)
    area = _area_history(org_id, location_terms, lookback_days)

    similar_high = sum(1 for item in similar if int(item.get("severity") or 1) >= 4)
    packet_confidence = round(
        min(
            0.99,
            max(
                0.0,
                (float(classification["threat_score"]) * 0.45)
                + (min(area["risk_rating"] == "Red" and 0.95 or area["risk_rating"] == "Orange" and 0.7 or 0.4, 0.95) * 0.25)
                + (min(len(similar), 10) / 10 * 0.15)
                + (min(similar_high, 5) / 5 * 0.15),
            ),
        ),
        3,
    )

    packet_id = hashlib.sha256(f"{org_id}|{incident_text[:200]}|{location}|{lookback_days}|{task}".encode("utf-8")).hexdigest()[:16]
    return {
        "packet_id": packet_id,
        "task": task,
        "org_id": org_id,
        "location": location,
        "classification": classification,
        "entities": entities,
        "area_history": area,
        "recent_similar_incidents": similar,
        "queries_needed": _queries_needed(classification),
        "routing_hints": _routing_hints(classification, location_terms, similar),
        "graph_payload": _graph_payload(packet_id, classification, location_terms, similar),
        "operational_notes": [
            "OSINT brain output only. Use relationship API for inventory, dispatch, or automation decisions.",
            "Treat this packet as decision support, not a command order.",
        ],
        "confidence": packet_confidence,
        "source_window_days": lookback_days,
        "generated_at": datetime.now(timezone.utc).astimezone().replace(microsecond=0).isoformat(),
    }
