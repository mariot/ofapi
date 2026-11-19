"""Intel 471 API (v1): the Titan malware indicators, YARA rules, CVE reports, IOCs and
GIRs (intel471 and intel471_v2 import connectors, titan backend), and the watcher alerts
with the reports and actors they link to (intel471-darknet import connector)."""

import time

from fastapi import APIRouter, Query, Request, Response

from app.fake import fake

HOSTS = ["api.intel471.com"]
router = APIRouter(prefix="/intel471", tags=["Intel 471"])

HOUR_MS = 3_600_000
FAMILIES = ["Qakbot", "IcedID", "Raccoon Stealer", "RedLine", "Cobalt Strike"]
TACTICS = ["Command and Control", "Execution", "Initial Access", "Exfiltration"]
GIRS = {
    "1.1.1": "Ransomware and extortion actors",
    "2.3": "Vulnerability exploitation",
    "4.2.1": "Malware development and distribution",
}


def _anchor() -> int:
    """A moment (ms) of the current hour: results dated from it are not new for a search
    starting after them, as the next poll of a connector does with its cursor."""
    return (int(time.time() * 1000) // HOUR_MS) * HOUR_MS - 600_000


def _unauthorized(request: Request) -> Response | None:
    if not request.headers.get("authorization", "").startswith("Basic "):
        return Response(status_code=401, content='{"error": "Unauthorized"}')
    return None


def _threat() -> dict:
    return {
        "type": "malware",
        "uid": fake.uuid4(),
        "data": {
            "family": fake.random_element(FAMILIES),
            "malware_family_profile_uid": fake.uuid4(),
            "version": f"{fake.random_int(1, 5)}.{fake.random_int(0, 9)}",
        },
    }


def _indicator(index: int, anchor: int) -> dict:
    kind = ["ipv4", "url", "file"][index % 3]
    indicator_data = {}
    if kind == "ipv4":
        indicator_data["address"] = fake.ipv4_public()
    elif kind == "url":
        indicator_data["url"] = fake.url()
    else:
        indicator_data["file"] = {
            "md5": fake.md5(),
            "sha1": fake.sha1(),
            "sha256": fake.sha256(),
            "size": fake.random_int(10_000, 900_000),
            "type": "PE32 executable",
        }
    return {
        "uid": fake.uuid4(),
        "activity": {"first": anchor - HOUR_MS + index, "last": anchor + index},
        "last_updated": anchor + index,
        "meta": {"version": "1.20.0"},
        "data": {
            "uid": fake.uuid4(),
            "confidence": fake.random_element(["high", "medium", "B2"]),
            "context": {"description": fake.sentence()},
            "expiration": anchor + 30 * 24 * HOUR_MS,
            "indicator_type": kind,
            "indicator_data": indicator_data,
            "intel_requirements": [fake.random_element(list(GIRS))],
            "mitre_tactics": fake.random_element(TACTICS),
            "threat": _threat(),
        },
    }


@router.get("/v1/indicators/stream")
async def indicators_stream(
    request: Request, cursor: str | None = None, count: int = 100
):
    """A page of indicators for a stream started without cursor; the next call, with
    the cursor it was given, finds nothing new."""
    if denied := _unauthorized(request):
        return denied
    if cursor:
        return {"cursorNext": cursor, "indicatorTotalCount": 0, "indicators": []}
    anchor = _anchor()
    indicators = [_indicator(i, anchor) for i in range(min(count, 6))]
    return {
        "cursorNext": fake.sha1(),
        "indicatorPartialResult": False,
        "indicatorTotalCount": len(indicators),
        "indicators": indicators,
    }


def _first_page(offset: int, from_: int, newest: int) -> bool:
    """Whether a search has results: its first page, if it starts before the newest
    (the next pages, or a search starting after the newest, have none)."""
    return offset == 0 and from_ <= newest


@router.get("/v1/yara")
async def yara(request: Request, from_: int = Query(0, alias="from"), offset: int = 0):
    if denied := _unauthorized(request):
        return denied
    anchor = _anchor()
    yaras = []
    if _first_page(offset, from_, anchor + 2):
        for index in range(3):
            family = fake.random_element(FAMILIES)
            name = family.replace(" ", "_")
            yaras.append(
                {
                    "uid": fake.uuid4(),
                    "activity": {
                        "first": anchor - HOUR_MS + index,
                        "last": anchor + index,
                    },
                    "last_updated": anchor + index,
                    "meta": {"version": "1.20.0"},
                    "data": {
                        "confidence": "high",
                        "intel_requirements": [fake.random_element(list(GIRS))],
                        "threat": {
                            "type": "malware",
                            "uid": fake.uuid4(),
                            "data": {
                                "family": family,
                                "malware_family_profile_uid": fake.uuid4(),
                                "version": "1.0",
                            },
                        },
                        "yara_data": {
                            "title": f"{name} loader",
                            "signature": (
                                f'rule {name}_{index} {{ meta: author = "Intel 471" '
                                f'strings: $a = "{fake.word()}" '
                                f"$b = {{ {fake.hexify('^^ ^^ ^^ ^^')} }} "
                                "condition: any of them }"
                            ),
                        },
                    },
                }
            )
    return {"yaraPartialResult": False, "yaraTotalCount": len(yaras), "yaras": yaras}


@router.get("/v1/cve/reports")
async def cve_reports(
    request: Request, from_: int = Query(0, alias="from"), offset: int = 0
):
    if denied := _unauthorized(request):
        return denied
    anchor = _anchor()
    reports = []
    if _first_page(offset, from_, anchor + 1):
        for index in range(2):
            product = fake.random_element(["Exchange Server", "FortiOS", "Confluence"])
            reports.append(
                {
                    "uid": fake.uuid4(),
                    "activity": {
                        "first": anchor - HOUR_MS + index,
                        "last": anchor + index,
                    },
                    "last_updated": anchor + index,
                    "classification": {
                        "intel_requirements": [fake.random_element(list(GIRS))]
                    },
                    "data": {
                        "cve_report": {
                            "name": fake.cve_id(),
                            "summary": fake.paragraph(),
                            "underground_activity": "Observed",
                            "underground_activity_summary": fake.paragraph(),
                            "counter_measures": fake.paragraph(),
                            "counter_measure_links": [],
                            "cpe": {},
                            "cve_status": "Published",
                            "cve_type": "Remote code execution",
                            "cvss_score": {"v2": 7.5, "v3": 9.8},
                            "detection": fake.sentence(),
                            "exploit_status": {
                                "available": True,
                                "not_observed": False,
                                "productized": False,
                                "weaponized": True,
                            },
                            "interest_level": {
                                "disclosed_publicly": True,
                                "exploit_sought": True,
                                "researched_publicly": False,
                            },
                            "activity_location": {
                                "location_opensource": True,
                                "location_private": False,
                                "location_underground": True,
                            },
                            "patch_status": "Available",
                            "patch_links": [
                                {"title": "Vendor advisory", "url": fake.url()}
                            ],
                            "poc": "Available",
                            "poc_links": [{"title": "Public PoC", "url": fake.url()}],
                            "product_name": product,
                            "vendor_name": fake.company(),
                            "risk_level": "High",
                            "titan_links": [
                                {"title": "Titan report", "url": fake.url()}
                            ],
                        }
                    },
                }
            )
    return {
        "cveReports": reports,
        "cveReportsTotalCount": len(reports),
        "postPartialResult": False,
    }


@router.get("/v1/iocs")
async def iocs(request: Request, from_: int = Query(0, alias="from"), offset: int = 0):
    if denied := _unauthorized(request):
        return denied
    anchor = _anchor()
    found = []
    if _first_page(offset, from_, anchor + 5):
        values = [
            ("MaliciousURL", fake.url()),
            ("MaliciousDomain", fake.domain_name()),
            ("IPAddress", fake.ipv4_public()),
            ("MD5", fake.md5()),
            ("SHA1", fake.sha1()),
            ("SHA256", fake.sha256()),
        ]
        for index, (kind, value) in enumerate(values):
            found.append(
                {
                    "uid": fake.uuid4(),
                    "type": kind,
                    "value": value,
                    "activeFrom": anchor - HOUR_MS,
                    "activeTill": anchor + 30 * 24 * HOUR_MS,
                    "ispCountryCode": "NL",
                    "ispName": fake.company(),
                    "lastUpdated": anchor + index,
                    "links": {
                        "actorTotalCount": 0,
                        "actors": [],
                        "reportTotalCount": 0,
                        "reports": [],
                    },
                }
            )
    return {"iocPartialResult": False, "iocTotalCount": len(found), "iocs": found}


@router.get("/v1/girs")
async def girs(request: Request, offset: int = 0):
    """The names of the general intelligence requirements, one page."""
    if denied := _unauthorized(request):
        return denied
    entries = []
    if offset == 0:
        entries = [
            {
                "uid": fake.uuid4(),
                "data": {
                    "gir": {
                        "path": path,
                        "name": name,
                        "description": fake.sentence(),
                        "parent": None,
                    }
                },
            }
            for path, name in GIRS.items()
        ]
    return {"girTotalCount": len(entries), "girs": entries, "partialResult": False}


def _stamp(offset_ms: int = 0) -> int:
    return _anchor() + offset_ms


@router.get("/v1/watcherGroups")
async def watcher_groups(request: Request) -> dict:
    if denied := _unauthorized(request):
        return denied
    return {
        "watcherGroups": [
            {"uid": "staticfire-group", "name": "OpenCTI", "description": "Watchers"}
        ]
    }


@router.get("/v1/watcherGroups/{group_uid}/watchers")
async def watchers(request: Request, group_uid: str) -> dict:
    if denied := _unauthorized(request):
        return denied
    return {
        "watchers": [
            {
                "uid": f"{group_uid}-watcher-{index}",
                "description": f"Watcher for {fake.company()}",
                "type": "search",
            }
            for index in range(2)
        ]
    }


def _entity(kind: str, value: str) -> dict:
    return {"type": kind, "value": value}


def _entities() -> list[dict]:
    return [
        _entity("MaliciousDomain", fake.domain_name()),
        _entity("IPAddress", fake.ipv4_public()),
        _entity("MaliciousURL", fake.url()),
        _entity("EmailAddress", fake.email()),
        _entity("MD5", fake.md5()),
        _entity("SHA256", fake.sha256()),
        _entity("CveID", fake.cve_id()),
        _entity("MalwareFamily", fake.random_element(FAMILIES)),
        _entity("Telegram", f"@{fake.user_name()}"),
        _entity("Tag", "ransomware"),
    ]


def _report_ref() -> dict:
    uid = fake.uuid4()
    return {
        "uid": uid,
        "subject": fake.sentence(),
        "portalReportUrl": f"https://titan.intel471.com/report/fintel/{uid}",
        "released": _stamp(),
        "dateOfInformation": _stamp(-HOUR_MS),
        "admiraltyCode": "B2",
    }


def _alert(anchor: int, index: int, content: dict) -> dict:
    return {
        "uid": fake.hexify("^" * 32),
        "foundTime": anchor + index,
        "watcherUid": "staticfire-group-watcher-0",
        **content,
    }


@router.get("/v1/alerts")
async def alerts(
    request: Request, from_: int = Query(0, alias="from"), offset: str | None = None
) -> dict:
    """One page of alerts, one of every kind the connector maps; the page after it
    (offset: the uid of the last alert) is empty."""
    if denied := _unauthorized(request):
        return denied
    anchor = _anchor()
    if offset or from_ > anchor + 10:
        return {"alerts": []}
    forum = {"name": fake.company(), "uid": fake.uuid4()}
    actor = {"handle": fake.user_name(), "uid": fake.uuid4()}
    now = _stamp()
    contents = [
        {
            "post": {
                "uid": fake.hexify("^" * 24),
                "message": f"<p>{fake.paragraph()}</p>",
                "date": now - HOUR_MS,
                "lastUpdated": now,
                "links": {
                    "authorActor": actor,
                    "forum": forum,
                    "thread": {"uid": fake.uuid4(), "topic": fake.sentence()},
                },
            }
        },
        {
            "privateMessage": {
                "uid": fake.hexify("^" * 24),
                "message": f"<p>{fake.paragraph()}</p>",
                "date": now - HOUR_MS,
                "lastUpdated": now,
                "links": {
                    "forum": forum,
                    "thread": {"uid": fake.uuid4()},
                    "authorActor": actor,
                    "recipientActor": {"handle": fake.user_name(), "uid": fake.uuid4()},
                },
            }
        },
        {
            "instantMessage": {
                "uid": fake.hexify("^" * 24),
                "activity": {"first": now - HOUR_MS, "last": now},
                "last_updated": now,
                "data": {
                    "message": {"text": f"<p>{fake.paragraph()}</p>"},
                    "channel": {
                        "name": f"{fake.word()}-{fake.word()}",
                        "url": f"https://t.me/{fake.user_name()}",
                    },
                    "server": {"service_type": "telegram"},
                    "actor": {"handle": fake.user_name()},
                },
            }
        },
        {"report": _report_ref()},
        {
            "spotReport": {
                "uid": fake.uuid4(),
                "last_updated": now,
                "data": {
                    "spot_report": {
                        "spot_report_data": {
                            "title": fake.sentence(),
                            "text": fake.paragraph(),
                            "date_of_information": now - HOUR_MS,
                            "released_at": now,
                            "victims": [{"name": fake.company(), "urls": [fake.url()]}],
                            "links": [{"title": "Reference", "url": fake.url()}],
                        }
                    },
                    "entities": _entities()[:5],
                },
            }
        },
        {
            "breachAlert": {
                "uid": fake.uuid4(),
                "last_updated": now,
                "data": {
                    "breach_alert": {
                        "title": fake.sentence(),
                        "date_of_information": now - HOUR_MS,
                        "released_at": now,
                        "confidence": {
                            "level": "high",
                            "description": fake.sentence(),
                        },
                        "summary": f"<p>{fake.paragraph()}</p>",
                        "actor_or_group": (
                            f"{fake.intrusion_set()} aka {fake.user_name()}"
                        ),
                        "sources": [{"title": "Leak site", "url": fake.url()}],
                        "victim": {
                            "name": fake.company(),
                            "urls": [fake.url()],
                            "country": "France",
                            "region": "Western Europe",
                            "industries": [
                                {"industry": "Software", "sector": "Technology"}
                            ],
                        },
                    },
                    "entities": _entities()[:3],
                },
            }
        },
        {
            "actor": {
                "uid": fake.uuid4(),
                "handles": [fake.user_name(), fake.user_name()],
                "lastUpdated": now,
                "activeFrom": now - 30 * 24 * HOUR_MS,
                "activeUntil": now,
                "links": {
                    "forumTotalCount": 2,
                    "forumPostTotalCount": 40,
                    "forums": [
                        {"name": forum["name"], "contactInfo": _entities()[3:4]}
                    ],
                    "reports": [_report_ref()],
                    "reportTotalCount": 1,
                },
            }
        },
        {
            "entity": {
                **_entity("MaliciousDomain", fake.domain_name()),
                "links": {
                    "actors": [{"uid": "staticfire-actor", "handle": fake.user_name()}],
                    "reports": [_report_ref()],
                },
            }
        },
    ]
    return {
        "alerts": [
            _alert(anchor, index, content) for index, content in enumerate(contents)
        ]
    }


@router.get("/v1/reports/{report_uid}")
async def report(request: Request, report_uid: str) -> dict:
    """The full text of a report, with the actors, victims and entities it names."""
    if denied := _unauthorized(request):
        return denied
    now = _stamp()
    return {
        "uid": report_uid,
        "subject": fake.sentence(),
        "sourceCharacterization": "Underground forum, regularly reliable",
        "admiraltyCode": "B2",
        "motivation": ["CC"],
        "portalReportUrl": f"https://titan.intel471.com/report/fintel/{report_uid}",
        "documentFamily": "FINTEL",
        "dateOfInformation": now - HOUR_MS,
        "released": now,
        "actorSubjectOfReport": [{"handle": fake.user_name(), "uid": fake.uuid4()}],
        "victims": [{"name": fake.company(), "urls": [fake.url()]}],
        "entities": _entities(),
        "locations": [
            {"region": "Eastern Europe", "country": "Russia", "link": "active_in"},
            {"country": "France", "link": "impacts"},
        ],
        "rawText": f"<p>{fake.paragraph()}</p>",
        "executiveSummary": f"<p>{fake.paragraph()}</p>",
        "researcherComments": f"<p>{fake.sentence()}</p>",
        "sources": [{"title": "Forum thread", "url": fake.url()}],
        "tags": ["ransomware", "initial-access"],
    }


@router.get("/v1/actors/{actor_uid}")
async def actor(request: Request, actor_uid: str) -> dict:
    if denied := _unauthorized(request):
        return denied
    now = _stamp()
    return {
        "uid": actor_uid,
        "handles": [fake.user_name(), fake.user_name()],
        "lastUpdated": now,
        "activeFrom": now - 30 * 24 * HOUR_MS,
        "activeUntil": now,
        "links": {
            "forumTotalCount": 1,
            "forumPostTotalCount": 12,
            "forums": [{"name": fake.company(), "contactInfo": _entities()[3:4]}],
            "reports": [],
            "reportTotalCount": 0,
        },
    }
