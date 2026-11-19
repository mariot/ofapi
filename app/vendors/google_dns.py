"""Google Public DNS (DNS-over-HTTPS JSON API), read by the OpenCTI google-dns
enrichment connector."""

from fastapi import APIRouter

from app.fake import fake

HOSTS = ["dns.google.com", "dns.google"]
router = APIRouter(prefix="/google-dns", tags=["Google DNS"])

TYPE_IDS = {"A": 1, "NS": 2, "CNAME": 5, "MX": 15, "TXT": 16}


def _answer(name: str, record_type: str, data: str) -> dict:
    return {
        "name": f"{name}.",
        "type": TYPE_IDS[record_type],
        "TTL": fake.random_int(60, 3600),
        "data": data,
    }


def _answers(name: str, record_type: str) -> list[dict]:
    """The records of one type, as a resolver returns them (names end with a dot)."""
    target = f"edge.{fake.domain_name()}"
    match record_type:
        case "A":
            return [_answer(name, "A", fake.ipv4_public()) for _ in range(2)]
        case "NS":
            return [_answer(name, "NS", f"ns{i}.{fake.domain_name()}.") for i in (1, 2)]
        case "CNAME":
            return [_answer(name, "CNAME", f"{target}.")]
        case "MX":
            return [
                _answer(name, "MX", f"{priority} mail{priority}.{fake.domain_name()}.")
                for priority in (10, 20)
            ]
        case "TXT":
            return [_answer(name, "TXT", '"v=spf1 include:_spf.example.com ~all"')]
    return []


@router.get("/resolve")
async def resolve(name: str, type: str = "A") -> dict:  # noqa: A002 - the API's name
    """A successful DoH JSON answer holding the records of the type asked."""
    answers = _answers(name.rstrip("."), type.upper())
    return {
        "Status": 0 if answers else 3,
        "TC": False,
        "RD": True,
        "RA": True,
        "AD": False,
        "CD": False,
        "Question": [{"name": f"{name}.", "type": TYPE_IDS.get(type.upper(), 1)}],
        **({"Answer": answers} if answers else {}),
    }
