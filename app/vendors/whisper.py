"""Whisper graph API: Cypher over POST /api/query, read by the whisper connector.

The Cypher text is read, not executed: the node name inlined in the query and the
shape of its MATCH/RETURN pick the rows the real graph would answer.
"""

import hashlib
import json
import re
import time

from fastapi import APIRouter, Header, HTTPException, Request

from app.fake import fake

HOSTS = ["graph.whisper.security"]
router = APIRouter(prefix="/whisper", tags=["Whisper"])

NAME = re.compile(r'\{name: ("(?:[^"\\]|\\.)*")\}')
REL = re.compile(r"\[(?:r)?:(\w+)\]")
TARGET = re.compile(r"\(m:(\w+)\)")
THREAT_FLAGS = ["isThreat", "isMalware", "isC2", "isPhishing", "isSpam", "isScanner"]


def _node(label: str, name: str) -> dict:
    digest = hashlib.sha1(f"{label}:{name}".encode()).hexdigest()[:12]
    return {"nodeId": f"{label.lower()}-{digest}", "label": label, "name": name}


def _name_for(label: str, seed: str) -> str:
    if label == "HOSTNAME":
        return f"{fake.word()}.{seed}" if "." in seed else fake.domain_name()
    if label == "IPV4":
        return fake.ipv4_public()
    if label == "IPV6":
        return fake.ipv6()
    if label == "ASN":
        return f"AS{fake.random_int(1000, 64000)}"
    if label == "REGISTRAR":
        return fake.random_element(["iana:292", "iana:146", "registrar:Gandi SAS"])
    if label == "ORGANIZATION":
        return fake.company()
    if label == "EMAIL":
        return fake.email()
    return fake.word()


def _now_ms(days_ago: int = 0) -> int:
    return int((time.time() - days_ago * 86400) * 1000)


def _answer(columns: list[str], rows: list[dict]) -> dict:
    return {
        "success": True,
        "columns": columns,
        "rows": rows,
        "statistics": {"executionTimeMs": 12, "rowCount": len(rows)},
    }


def _links(seed: str, count: int = 2) -> dict:
    hosts = [_node("HOSTNAME", fake.domain_name()) for _ in range(count)]
    edge = {"type": "LINKS_TO"}
    rows = [{"n": _node("HOSTNAME", seed), "r": edge, "m": h} for h in hosts]
    return _answer(["n", "r", "m"], rows)


def _main(seed: str, label: str) -> dict:
    """The one-hop neighbourhood of an IP or ASN seed."""
    rows = []
    for edge, other in [
        ("RESOLVES_TO", "HOSTNAME"),
        ("RESOLVES_TO", "HOSTNAME"),
        ("LOCATED_IN", "COUNTRY"),
        ("LOCATED_IN", "CITY"),
        ("BELONGS_TO", "ASN"),
        ("LISTED_IN", "FEED_SOURCE"),
    ]:
        if label == "ASN" and other == "ASN":
            continue
        if other == "COUNTRY":
            name = fake.country_code()
        elif other == "CITY":
            name = f"{fake.city()}, {fake.country_code()}"
        elif other == "FEED_SOURCE":
            name = "blocklist_de"
        else:
            name = _name_for(other, seed)
        row = {"n": _node(label, seed), "r": {"type": edge}, "m": _node(other, name)}
        rows.append(row)
    return _answer(["n", "r", "m"], rows)


def _threat() -> dict:
    flags = {flag: flag in ("isThreat", "isMalware") for flag in THREAT_FLAGS}
    base = {
        "threatScore": 72,
        "threatLevel": "HIGH",
        **flags,
        "threatFirstSeen": _now_ms(40),
        "threatLastSeen": _now_ms(1),
    }
    rows = [
        {
            **base,
            "feedName": feed,
            "feedFirstSeen": _now_ms(30),
            "feedLastSeen": _now_ms(2),
            "feedWeight": 0.8,
        }
        for feed in ("blocklist_de", "firehol_level1")
    ]
    columns = list(rows[0])
    return _answer(columns, rows)


def _network(seed: str) -> dict:
    asn = _node("ASN", f"AS{fake.random_int(1000, 64000)}")
    ipv4 = "." in seed
    prefix = f"{'.'.join(seed.split('.')[:2])}.0.0/16" if ipv4 else "2001:db8::/32"
    row = {
        "seed": _node("IPV4" if ipv4 else "IPV6", seed),
        "asn": asn,
        "asnDescription": fake.company(),
        "announcedPrefix": prefix,
        "apThreatScore": 15,
        "apThreatLevel": "LOW",
        "isAnycast": False,
        "isMoas": False,
        "isWithdrawn": False,
        "prefix": prefix,
    }
    return _answer(list(row), [row])


def _facts(query: str, seed: str) -> dict:
    relation = REL.search(query)
    target = TARGET.search(query)
    label = target.group(1) if target else "HOSTNAME"
    rows = [
        {"h": _node("HOSTNAME", seed), "m": _node(label, _name_for(label, seed))}
        for _ in range(2 if label in ("IPV4", "HOSTNAME") else 1)
    ]
    if relation is None:
        rows = []
    return _answer(["h", "m"], rows)


def run_cypher(query: str) -> dict:
    """The rows a graph holding data on every name would return for ``query``."""
    named = NAME.search(query)
    seed = json.loads(named.group(1)) if named else ""
    if query.startswith("UNWIND"):
        candidates = json.loads("[" + query.split("[", 1)[1].split("]", 1)[0] + "]")
        return _answer(["name"], [{"name": name} for name in candidates[:2]])
    if "count(m) AS c" in query:
        return _answer(["c"], [{"c": 3}])
    if "[r:LINKS_TO]" in query:
        return _links(seed)
    if 'STARTS WITH "SPF_"' in query:
        rows = [
            {"spfType": "SPF_INCLUDE", "target": "_spf.google.com"},
            {"spfType": "SPF_IP4", "target": fake.ipv4_public()},
            {"spfType": "SPF_ALL", "target": "~all"},
        ]
        return _answer(["spfType", "target"], rows)
    if "HAS_PHONE" in query:
        return _answer(["phone"], [{"phone": "+33.140000000"}])
    if "threatScore" in query and "ANNOUNCED_BY" not in query:
        return _threat()
    if "ANNOUNCED_BY" in query:
        return _network(seed)
    if "RETURN n, r, m" in query:
        label = re.search(r"\(n:(\w+)", query).group(1)
        return _main(seed, label)
    if "RETURN h, m" in query:
        return _facts(query, seed)
    return _answer([], [])


@router.post("/api/query")
async def query(request: Request, x_api_key: str | None = Header(None)) -> dict:
    """Run a Cypher query; the key travels in X-API-Key."""
    if not x_api_key:
        raise HTTPException(401, "missing API key")
    body = await request.json()
    return run_cypher(body.get("query", ""))
