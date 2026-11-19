"""CRITs: the REST API (tastypie) read by the OpenCTI crits connector.

CRITs lists every collection (ips, domains, samples...) under ``/api/v1/<collection>/``
with ``meta`` (``limit``, ``offset``, ``total_count``) and ``objects``, and each object
under ``/api/v1/<collection>/<id>/``. Events (which relate to other objects) are only
returned to the user ``staticfire-events``, so that two scenarios use the same fake.
"""

import base64
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, HTTPException, Query

from app.fake import fake

HOSTS = ["crits.staticfire.test"]
router = APIRouter(prefix="/crits", tags=["CRITs"])

EVENTS_USER = "staticfire-events"
STAMP = "%Y-%m-%d %H:%M:%S.%f"
YARA = 'rule staticfire_{n} {{ strings: $a = "{s}" condition: $a }}'

_data: dict[str, list[dict]] = {}


def _oid() -> str:
    return fake.sha1()[:24]


def _when() -> str:
    return (datetime.now(UTC) - timedelta(days=fake.random_int(1, 20))).strftime(STAMP)


def _source() -> list[dict]:
    return [
        {
            "name": fake.random_element(["Staticfire SOC", "Partner CERT"]),
            "instances": [
                {
                    "analyst": "analyst1",
                    "date": _when(),
                    "method": "manual entry",
                    "reference": fake.random_element([fake.url(), "TICKET-4711", ""]),
                }
            ],
        }
    ]


def _base(**fields) -> dict:
    return {
        "_id": _oid(),
        "source": _source(),
        "relationships": [],
        "campaign": [],
        "bucket_list": fake.random_elements(["apt", "phishing", "c2"], 2, unique=True),
        "description": fake.sentence(),
        "created": _when(),
        "modified": _when(),
        "status": "New",
        **fields,
    }


def _relate(source: dict, target: dict, kind: str) -> None:
    source["relationships"].append(
        {
            "type": kind,
            "value": target["_id"],
            "rel_type": "Related To",
            "rel_reason": fake.sentence(),
            "rel_confidence": "medium",
            "relationship_date": _when(),
            "analyst": "analyst1",
            "date": _when(),
        }
    )


def _build() -> dict[str, list[dict]]:
    ips = [_base(ip=fake.ipv4_public(), type="IPv4 Address") for _ in range(4)]
    ips.append(_base(ip=fake.ipv6(), type="IPv6 Address"))
    _relate(ips[0], ips[1], "IP")
    domains = [_base(domain=fake.domain_name()) for _ in range(2)]
    raw_data = [
        _base(
            title="Beacon configuration",
            data=f"c2={fake.domain_name()};sleep=60",
            data_type="Text",
        )
    ]
    content = fake.sha256().encode()
    samples = [
        _base(
            md5=fake.md5(),
            sha1=fake.sha1(),
            sha256=fake.sha256(),
            ssdeep=fake.ssdeep(),
            size=len(content),
            mimetype="application/x-dosexec",
            filename="invoice.exe",
            filenames=["invoice.exe", "scan.exe"],
            filedata=base64.b64encode(content).decode() if i == 0 else None,
        )
        for i in range(2)
    ]
    campaigns = [_base(name=f"Operation {fake.word().title()}", aliases=["OpX"])]
    actors = [_base(name=fake.intrusion_set(), aliases=[fake.word()])]
    backdoors = [_base(name=fake.malware_family(), aliases=[])]
    exploits = [_base(name=f"Exploit {fake.cve_id()}", cve=fake.cve_id())]
    indicators = [
        _base(type="Domain", value=fake.domain_name()),
        _base(type="SHA256", value=fake.sha256()),
        _base(type="IPv4 Address", value=fake.ipv4_public()),
        _base(type="URI", value=fake.url()),
        _base(type="Registry Key", value="HKLM\\Software\\Run\\x"),
    ]
    signatures = [
        _base(
            title=f"Staticfire rule {i}",
            data=YARA.format(n=i, s=fake.word()),
            data_type="YARA",
            data_type_max_version=4.2,
        )
        for i in range(2)
    ]
    emails = [
        _base(
            subject="Invoice overdue",
            raw_headers=(
                "Received: from mail.example.org by mx.example.net\n"
                "From: billing@example.org\nContent-Type: text/plain\n"
                "X-Mailer: Mailer 1.0"
            ),
            raw_body="Please see the attached invoice.",
            message_id=f"<{fake.uuid4()}@example.org>",
            isodate=_when().replace(" ", "T"),
        )
    ]
    targets = [
        _base(
            email_address=fake.email(),
            firstname=fake.first_name(),
            lastname=fake.last_name(),
            title="Accountant",
        )
    ]
    events = [
        _base(
            title="Spearphishing wave",
            campaign=[{"name": campaigns[0]["name"]}],
        )
    ]
    for kind, items in (("IP", ips[:1]), ("Domain", domains[:1])):
        for item in items:
            _relate(events[0], item, kind)
    _relate(events[0], samples[0], "Sample")
    return {
        "events": events,
        "ips": ips,
        "domains": domains,
        "raw_data": raw_data,
        "samples": samples,
        "campaigns": campaigns,
        "actors": actors,
        "backdoors": backdoors,
        "exploits": exploits,
        "indicators": indicators,
        "signatures": signatures,
        "emails": emails,
        "targets": targets,
    }


def _collection(name: str) -> list[dict]:
    if not _data:
        _data.update(_build())
    if name not in _data:
        raise HTTPException(404, f"unknown collection {name}")
    return _data[name]


@router.get("/api/v1/{collection}/")
async def objects(
    collection: str,
    username: str = "",
    api_key: str = "",
    limit: int = 20,
    offset: int = 0,
    name: str | None = Query(None, alias="c-name"),
) -> dict:
    """A page of a collection (events only for the events user), 401 without a key."""
    if not api_key:
        raise HTTPException(401, "Unauthorized")
    items = _collection(collection)
    if collection == "events" and username != EVENTS_USER:
        items = []
    if name is not None:
        items = [i for i in items if i.get("name") == name]
    page = items[offset : offset + limit]
    return {
        "meta": {
            "limit": limit,
            "offset": offset,
            "next": None,
            "previous": None,
            "total_count": len(items),
        },
        "objects": page,
    }


@router.get("/api/v1/{collection}/{object_id}/")
async def get_object(collection: str, object_id: str, api_key: str = "") -> dict:
    """One object by its id."""
    if not api_key:
        raise HTTPException(401, "Unauthorized")
    for item in _collection(collection):
        if item["_id"] == object_id:
            return item
    raise HTTPException(404, "Not found")
