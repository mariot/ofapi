"""RiskIQ PassiveTotal: account quota and passive DNS, read by the OpenCTI
riskiq-passive-total enrichment connector."""

from fastapi import APIRouter

from app.fake import fake

HOSTS = ["api.riskiq.net"]
router = APIRouter(prefix="/riskiq", tags=["RiskIQ"])


def _record(query: str, record_type: str, resolve_type: str, resolve: str) -> dict:
    first = fake.date_time_between("-300d", "-60d")
    last = fake.date_time_between(first, "-1d")
    return {
        "value": query,
        "recordType": record_type,
        "resolveType": resolve_type,
        "resolve": resolve,
        "firstSeen": first.strftime("%Y-%m-%d %H:%M:%S"),
        "lastSeen": last.strftime("%Y-%m-%d %H:%M:%S"),
        "collected": last.strftime("%Y-%m-%d %H:%M:%S"),
        "source": ["riskiq", "pingly"],
        "recordHash": fake.sha256()[:32],
    }


@router.get("/pt/v2/account/quota")
async def quota() -> dict:
    """A searchApi quota with plenty left."""
    return {
        "user": {
            "licenseLimits": {"searchApi": 15000, "whoisApi": 1000},
            "licenseCounts": {"searchApi": fake.random_int(1, 500), "whoisApi": 0},
            "next_reset": fake.future_date().isoformat() + " 00:00:00",
        }
    }


@router.get("/pt/v2/dns/passive")
async def passive_dns(query: str) -> dict:
    """Passive DNS records of a name: addresses, servers, aliases, SOA contact."""
    results = [
        _record(query, "A", "ip", fake.ipv4_public()),
        _record(query, "A", "ip", fake.ipv4_public()),
        _record(query, "AAAA", "ip", fake.ipv6()),
        _record(query, "SOA", "email", fake.email()),
        _record(query, "SOA", "domain", f"ns1.{fake.domain_name()}"),
        _record(query, "MX", "domain", f"mail.{fake.domain_name()}"),
        _record(query, "NS", "domain", f"ns2.{fake.domain_name()}"),
        _record(query, "CNAME", "domain", f"cdn.{fake.domain_name()}"),
        _record(query, "A", "domain", fake.domain_name()),
        _record(query, "TXT", "text", "v=spf1 -all"),
    ]
    return {
        "totalRecords": len(results),
        "queryValue": query,
        "firstSeen": min(r["firstSeen"] for r in results),
        "lastSeen": max(r["lastSeen"] for r in results),
        "results": results,
    }
