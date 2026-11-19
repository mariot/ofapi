"""CrowdStrike Falcon: Intel (actors, indicators, malware, reports, rules,
vulnerabilities), Alerts, NG-SIEM search, Recon notifications and IOC management, read
through falconpy by the OpenCTI crowdstrike, crowdstrike-incidents, crowdstrike-recon
and crowdstrike-endpoint-security connectors.

Falcon's OAuth2 token and the OpenAEV collector's alert routes stay in ``app/main.py``
(same ``/crowdstrike`` prefix). ``attack.staticfire.test`` serves the ATT&CK dataset the
crowdstrike connector loads from ``CROWDSTRIKE_ATTACK_ENTERPRISE_URL``.
"""

import io
import re
import zipfile
from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException, Request, Response

from app.fake import fake

HOSTS = ["api.crowdstrike.com", "api.*.crowdstrike.com", "attack.staticfire.test"]
router = APIRouter(prefix="/crowdstrike", tags=["CrowdStrike"])

DAY = 86400


def _now() -> int:
    return int(datetime.now(UTC).timestamp())


def _iso(epoch: float, fraction: int = 3) -> str:
    moment = datetime.fromtimestamp(epoch, UTC)
    text = moment.strftime("%Y-%m-%dT%H:%M:%S")
    if fraction:
        text += "." + f"{moment.microsecond:06d}".ljust(fraction, "0")[:fraction]
    return text + "Z"


def _envelope(resources: list, offset: int = 0, limit: int = 100, total=None) -> dict:
    return {
        "meta": {
            "query_time": 0.012,
            "pagination": {
                "limit": limit,
                "offset": offset,
                "total": len(resources) if total is None else total,
            },
            "powered_by": "falcon-intel-api",
            "trace_id": fake.uuid4(),
        },
        "resources": resources,
        "errors": [],
    }


def _page(items: list, offset: int, limit: int) -> dict:
    return _envelope(items[offset : offset + limit], offset, limit, len(items))


def _threshold(query: str, field: str) -> str | None:
    """The value of ``<field>:>[=]<value>`` in an FQL filter."""
    match = re.search(rf"{field}:>=?'?([^'+,)\s]+)'?", query or "")
    return match.group(1) if match else None


def _epoch(value: str | None) -> float:
    if value is None:
        return 0
    if value.isdigit():
        return int(value)
    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


# Actors, reports and the rules that name them share these codes.
ACTORS = [
    ("FANCY BEAR", "fancy-bear", "Russia", "ru", "Espionage", "Fancy Bear, Sofacy"),
    ("WICKED SPIDER", "wicked-spider", "China", "cn", "Criminal", "Wicked Panda"),
    (
        "LABYRINTH CHOLLIMA",
        "labyrinth-chollima",
        "North Korea",
        "kp",
        "State-Sponsored",
        "Lazarus Group",
    ),
]
FAMILIES = ["Mofksys", "PlugX", "AppleJeus", "Cobalt Strike"]
REPORT_CODES = ["CSA-260101", "CSIT-26002", "CSIR-26003"]
TECHNIQUES = [
    ("T1001", "Data Obfuscation", "Command and Control"),
    ("T1566", "Phishing", "Initial Access"),
    ("T1059", "Command and Scripting Interpreter", "Execution"),
]


def _actor(index: int) -> dict:
    name, slug, country, code, motivation, known_as = ACTORS[index]
    modified = _now() - (index + 1) * DAY
    return {
        "id": 1000 + index,
        "name": name,
        "slug": slug,
        "url": f"https://falcon.crowdstrike.com/intelligence/actors/{slug}",
        "description": f"{name} is a long-running adversary.",
        "rich_text_description": f"<p>{name} is a long-running adversary.</p>",
        "short_description": f"{name} adversary",
        "known_as": known_as,
        "actor_type": "targeted",
        "motivations": [
            {"id": 1, "slug": motivation.lower(), "value": motivation},
            {"id": 2, "slug": "criminal", "value": "Criminal"},
        ],
        "origins": [{"id": 10 + index, "slug": code, "value": country}],
        "target_countries": [
            {"id": 20, "slug": "us", "value": "United States"},
            {"id": 21, "slug": "europe", "value": "Europe"},
            {"id": 22, "slug": "unknown", "value": "Unknown"},
        ],
        "target_industries": [
            {"id": 30, "slug": "financial-services", "value": "Financial Services"},
            {"id": 31, "slug": "government", "value": "Government"},
        ],
        "uses_threats": [
            {"family_name": FAMILIES[index]},
            {"family_name": FAMILIES[3]},
        ],
        "develops_threats": [{"family_name": FAMILIES[index]}],
        "first_activity_date": _now() - 900 * DAY,
        "last_activity_date": _now() - 3 * DAY,
        "created_date": _now() - 1500 * DAY,
        "last_modified_date": modified,
    }


def _report(index: int) -> dict:
    code = REPORT_CODES[index]
    actor = _actor(index % len(ACTORS))
    modified = _now() - (index + 1) * DAY
    return {
        "id": 5000 + index,
        "name": f"{code.upper()}: {fake.catch_phrase()}",
        "slug": code.lower(),
        "url": f"https://falcon.crowdstrike.com/intelligence/reports/{code.lower()}",
        "type": {"id": 1, "slug": "notice", "name": "Notice"},
        "created_date": modified - DAY,
        "last_modified_date": modified,
        "description": f"Activity of {actor['name']} against {fake.company()}.",
        "rich_text_description": "<p>Intrusion activity observed this week.</p>",
        "short_description": "Intrusion activity",
        "tags": [{"id": 1, "slug": "phishing", "value": "Phishing"}],
        "actors": [{"id": actor["id"], "name": actor["name"], "slug": actor["slug"]}],
        "malware": [{"id": 7, "family_name": FAMILIES[index % len(FAMILIES)]}],
        "target_industries": [
            {"id": 30, "slug": "financial-services", "value": "Financial Services"}
        ],
        "target_countries": [{"id": 20, "slug": "us", "value": "United States"}],
    }


def _label(name: str) -> dict:
    return {
        "name": name,
        "created_on": _now() - 5 * DAY,
        "last_valid_on": _now() - DAY,
    }


# (type, value factory, published days ago)
INDICATORS = [
    ("ip_address", fake.ipv4_public, 2),
    ("domain", fake.domain_name, 3),
    ("url", fake.url, 3),
    ("hash_sha256", fake.sha256, 4),
    ("hash_md5", fake.md5, 4),
    ("hash_sha1", fake.sha1, 5),
    ("email_address", fake.email, 5),
    ("file_name", lambda: fake.file_name(extension="dll"), 6),
    ("mutex_name", lambda: f"Global\\{fake.md5()[:10]}", 6),
    ("user_agent", fake.user_agent, 7),
    ("ip_address_block", lambda: fake.ipv4_public().rsplit(".", 1)[0] + ".0/24", 7),
    # Older than the maximum age of IP addresses: the connector skips it
    ("ip_address", fake.ipv4_public, 200),
]


def _indicator(index: int) -> dict:
    kind, factory, age = INDICATORS[index]
    value = factory()
    updated = _now() - (len(INDICATORS) - index) * 3600
    actor = ACTORS[index % len(ACTORS)][0].replace(" ", "")
    return {
        "id": f"{kind}_{value}",
        "indicator": value,
        "type": kind,
        "_marker": f"{updated}{index:03d}{fake.md5()[:6]}",
        "published_date": _now() - age * DAY,
        "last_updated": updated,
        "malicious_confidence": fake.random_element(["high", "medium", "low"]),
        "kill_chains": ["C2", "Installation"],
        "malware_families": [FAMILIES[index % len(FAMILIES)]],
        "targets": ["Financial", "Government"],
        "vulnerabilities": [fake.cve_id()] if index % 3 == 0 else [],
        "actors": [actor],
        "reports": [REPORT_CODES[index % len(REPORT_CODES)]],
        "threat_types": ["Commodity", "Criminal"],
        "domain_types": ["DGA"] if kind == "domain" else [],
        "ip_address_types": ["Proxy"] if kind == "ip_address" else [],
        "relations": [],
        "labels": [
            _label("MaliciousConfidence/High"),
            _label(f"Malware/{FAMILIES[index % len(FAMILIES)].replace(' ', '')}"),
            _label(f"Actor/{actor}"),
            _label("ThreatType/Commodity"),
            _label(
                "MITRE ATT&CK/Command and Control/Data Obfuscation"
                if index % 2
                else "MITRE ATT&CK/Initial Access/Phishing"
            ),
        ],
    }


def _malware(index: int) -> dict:
    name = FAMILIES[index]
    updated = _now() - (index + 1) * DAY
    return {
        "id": f"malware_{name.lower().replace(' ', '-')}",
        "name": name,
        "slug": name.lower().replace(" ", "-"),
        "description": f"<p>{name} is a modular implant.</p>",
        "created_timestamp": updated - 400 * DAY,
        "last_updated": updated,
        "community_identifiers": [f"{name}Loader"],
        "capabilities": ["Backdoor", "Botnet", "RemoteAccess"],
        "kill_chain": ["C2", "Installation"],
        "target_industries": [{"id": 30, "name": "Financial Services"}],
        "variant_of": [{"id": 1, "name": f"{name} Classic"}],
        "next_stage_of": [{"id": 2, "name": "Generic Dropper"}],
        "mitre": [
            {"technique_id": tid, "technique_name": tname, "tactic_name": tactic}
            for tid, tname, tactic in TECHNIQUES[:2]
        ],
    }


def _vulnerability(index: int) -> dict:
    updated = _now() - (index + 1) * DAY
    return {
        "id": f"vuln_{index}",
        "cve": fake.cve_id(),
        "description": f"<p>{fake.sentence()}</p>",
        "publish_date": _iso(updated - 10 * DAY, 0),
        "updated_timestamp": _iso(updated, 0),
        "cvss_v3_base": {
            "score": 9.8,
            "severity": "CRITICAL",
            "attack_vector": "NETWORK",
            "attack_complexity": "LOW",
            "privileges_required": "NONE",
            "user_interaction": "NONE",
            "scope": "UNCHANGED",
            "confidentiality_impact": "HIGH",
            "integrity_impact": "HIGH",
            "availability_impact": "HIGH",
        },
        "cvss_v2_base": {
            "score": 7.5,
            "access_vector": "NETWORK",
            "access_complexity": "LOW",
            "authentication": "NONE",
            "confidentiality_impact": "PARTIAL",
            "integrity_impact": "PARTIAL",
            "availability_impact": "PARTIAL",
        },
        "affected_products": [{"vendor": "Microsoft", "product": "Windows Server"}],
        "related_actors": [{"name": ACTORS[index % len(ACTORS)][0]}],
    }


@router.get("/intel/combined/actors/v1")
async def combined_actors(
    limit: int = 50,
    offset: int = 0,
    filter: str = "",  # noqa: A002
) -> dict:
    actors = [_actor(i) for i in range(len(ACTORS))]
    name = re.search(r"\(name:'([^']*)'\)", filter)
    if name:
        wanted = name.group(1).replace("\\", "").replace(" ", "").upper()
        actors = [a for a in actors if a["name"].replace(" ", "") == wanted]
    since = _threshold(filter, "last_modified_date")
    if since:
        actors = [a for a in actors if a["last_modified_date"] > _epoch(since)]
    actors.sort(key=lambda a: a["last_modified_date"])
    return _page(actors, offset, limit)


@router.get("/intel/queries/mitre/v1")
async def mitre_attacks(id: str = "") -> dict:  # noqa: A002
    actors = {str(1000 + i): ACTORS[i][1] for i in range(len(ACTORS))}
    slug = actors.get(id, "unknown")
    resources = [f"{slug}_TA0001_{tid}" for tid, _, _ in TECHNIQUES]
    return _envelope(resources)


@router.get("/intel/combined/indicators/v1")
async def combined_indicators(
    limit: int = 100,
    filter: str = "",  # noqa: A002
) -> dict:
    indicators = [_indicator(i) for i in range(len(INDICATORS))]
    report = re.search(r"reports:\['([^']*)'\]", filter)
    if report:
        code = report.group(1).lower()
        indicators = [
            i for i in indicators if any(r.lower() == code for r in i["reports"])
        ]
    excluded = re.search(r"type:!\[(.*?)\]", filter)
    if excluded:
        names = set(re.findall(r"'([^']+)'", excluded.group(1)))
        indicators = [i for i in indicators if i["type"] not in names]
    marker = re.search(r"_marker:>='([^']*)'", filter)
    if marker:
        indicators = [i for i in indicators if i["_marker"] >= marker.group(1)]
    indicators.sort(key=lambda i: i["_marker"])
    return _envelope(indicators[:limit], 0, limit, len(indicators))


@router.get("/intel/combined/malware/v1")
async def combined_malware(
    limit: int = 50,
    offset: int = 0,
    filter: str = "",  # noqa: A002
) -> dict:
    malware = [_malware(i) for i in range(len(FAMILIES))]
    since = _threshold(filter, "last_updated")
    if since:
        malware = [m for m in malware if m["last_updated"] > _epoch(since)]
    malware.sort(key=lambda m: m["last_updated"])
    return _page(malware, offset, limit)


@router.get("/intel/combined/reports/v1")
async def combined_reports(
    limit: int = 30,
    offset: int = 0,
    filter: str = "",  # noqa: A002
) -> dict:
    reports = [_report(i) for i in range(len(REPORT_CODES))]
    since = _threshold(filter, "last_modified_date")
    if since:
        reports = [r for r in reports if r["last_modified_date"] > _epoch(since)]
    created = _threshold(filter, "created_date")
    if created:
        reports = [r for r in reports if r["created_date"] > _epoch(created)]
    reports.sort(key=lambda r: r["last_modified_date"])
    return _page(reports, offset, limit)


@router.get("/intel/entities/reports/v1")
async def report_entities(request: Request) -> dict:
    codes = {c.lower() for c in request.query_params.getlist("ids")}
    reports = [
        r
        for r in (_report(i) for i in range(len(REPORT_CODES)))
        if r["slug"] in codes or str(r["id"]) in codes
    ]
    return _envelope(reports)


def _pdf(text: str) -> bytes:
    stream = f"BT /F1 12 Tf 72 720 Td ({text}) Tj ET".encode()
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R "
        b"/Resources << /Font << /F1 5 0 R >> >> >>",
        b"<< /Length %d >>\nstream\n%s\nendstream" % (len(stream), stream),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    out, offsets = b"%PDF-1.4\n", []
    for number, body in enumerate(objects, 1):
        offsets.append(len(out))
        out += b"%d 0 obj\n%s\nendobj\n" % (number, body)
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1)
    for offset in offsets:
        out += b"%010d 00000 n \n" % offset
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (
        len(objects) + 1,
        xref,
    )
    return out


@router.get("/intel/entities/report-files/v1")
async def report_file() -> Response:
    return Response(
        _pdf("CrowdStrike finished intelligence report"), media_type="application/pdf"
    )


def _zip(name: str, content: str) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr(name, content)
    return buffer.getvalue()


def _yara() -> str:
    rules = []
    for index in range(3):
        actor = ACTORS[index][0]
        rules.append(
            f"rule CS_Intel_Rule_{index}\n"
            "{\n"
            "  meta:\n"
            f'    description = "Detects {FAMILIES[index]} implants"\n'
            f'    last_modified = "2026-11-0{index + 1}"\n'
            f'    reports = "{REPORT_CODES[index]}"\n'
            f'    actor = "{actor}"\n'
            f'    malware_family = "{FAMILIES[index]}"\n'
            "  strings:\n"
            f'    $a = "{fake.word()}{index}" ascii\n'
            "  condition:\n"
            "    $a\n"
            "}\n"
        )
    return "\n".join(rules)


def _snort() -> str:
    return "\n".join(
        f'alert tcp $HOME_NET any -> $EXTERNAL_NET 443 (msg: "CS C2 beacon '
        f'[{REPORT_CODES[index]}]"; flow:established,to_server; '
        f'content:"{fake.word()}"; '
        f"sid:{9000000 + index}; rev:2026110{index + 1};)"
        for index in range(3)
    )


@router.get("/intel/entities/rules-latest-files/v1")
async def latest_rule_file(type: str = "") -> Response:  # noqa: A002
    if type == "yara-master":
        content = _zip("crowdstrike_intel_yara.yara", _yara())
    elif type == "snort-suricata-master":
        content = _zip("crowdstrike_intel_snort.rules", _snort())
    else:
        raise HTTPException(400, "Unknown rule set type")
    return Response(content, media_type="application/zip")


@router.get("/intel/queries/vulnerabilities/v1")
async def query_vulnerabilities(limit: int = 50, offset: int = 0) -> dict:
    ids = [_vulnerability(i)["id"] for i in range(3)]
    return _page(ids, offset, limit)


@router.post("/intel/entities/vulnerabilities/GET/v1")
async def vulnerability_entities(request: Request) -> dict:
    ids = (await request.json()).get("ids", [])
    wanted = set(ids)
    return _envelope(
        [v for v in (_vulnerability(i) for i in range(3)) if v["id"] in wanted]
    )


@router.get("/enterprise-attack.json")
async def attack_dataset() -> dict:
    """The few ATT&CK Enterprise techniques the fake indicators and actors refer to."""
    objects = [
        {
            "type": "attack-pattern",
            "spec_version": "2.1",
            "id": f"attack-pattern--{fake.uuid4()}",
            "created": "2018-04-18T17:59:24.739Z",
            "modified": "2024-10-15T00:00:00.000Z",
            "name": name,
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": tid,
                    "url": f"https://attack.mitre.org/techniques/{tid}",
                }
            ],
        }
        for tid, name, _ in TECHNIQUES
    ]
    return {"type": "bundle", "id": f"bundle--{fake.uuid4()}", "objects": objects}


def _alert(index: int) -> dict:
    created = _now() - (index + 1) * 3600
    stamp = _iso(created, 9)
    indicator = fake.md5()
    return {
        "agent_id": fake.md5(),
        "aggregate_id": f"aggind:{fake.md5()}:{index:010d}",
        "cid": fake.md5(),
        "composite_id": f"{fake.md5()}:ngsiem:{fake.md5()}:{indicator}",
        "created_timestamp": stamp,
        "updated_timestamp": stamp,
        "crawled_timestamp": stamp,
        "description": "Correlation rule detecting suspicious activity",
        "detection_id": f"{fake.md5()}:{indicator}",
        "display_name": fake.random_element(
            ["Suspicious PowerShell", "Credential Dumping", "Rare Service Install"]
        ),
        "name": "Correlation rule",
        "start_time": _iso(created - 60),
        "end_time": _iso(created),
        "event_ids": fake.uuid4(),
        "falcon_host_link": f"https://falcon.crowdstrike.com/unified-detections/{indicator}",
        "host_names": [f"host-{index}.corp.example.org"],
        "mitre_attack": [
            {
                "tactic_id": "TA0002",
                "tactic": "Execution",
                "technique_id": "T1059.001",
                "technique": "PowerShell",
            },
            {
                "tactic_id": "TA0005",
                "tactic": "Defense Evasion",
                "technique_id": "CS0001",
                "technique": "Proprietary technique",
            },
        ],
        "priority_explanation": ["Rare activity on this host"],
        "priority_value": 40 + index,
        "product": "ngsiem",
        "severity": 70,
        "severity_name": fake.random_element(["Critical", "High", "Medium", "Low"]),
        "show_in_ui": True,
        "source_ips": [fake.ipv4_private()],
        "status": "new",
        "type": "correlation-detection",
        "user_names": [fake.user_name()],
        "users": [
            {
                "sid": f"S-1-5-21-1-2-3-{1000 + index}",
                "user_name": fake.user_name(),
            }
        ],
    }


@router.post("/alerts/combined/alerts/v1")
async def combined_alerts(request: Request) -> dict:
    """Every alert at or after the cursor: one page (no ``after`` token)."""
    body = await request.json()
    cursor = re.search(r"updated_timestamp:>=?'([^']+)'", body.get("filter", ""))
    alerts = [_alert(i) for i in range(3)]
    if cursor:
        since = _epoch(cursor.group(1))
        alerts = [a for a in alerts if _epoch(a["updated_timestamp"]) >= since]
    alerts.sort(key=lambda a: a["updated_timestamp"])
    return _envelope(alerts, 0, body.get("limit", 1000), len(alerts))


# NG-SIEM (LogScale) searches: a job remembers the alert indicator ids it was asked for
_JOBS: dict[str, list[str]] = {}


@router.post("/humio/api/v1/repositories/{repository}/queryjobs")
async def start_search(request: Request) -> dict:
    query = (await request.json()).get("queryString", "")
    ids = re.findall(r'"([A-Za-z0-9_-]+)"', query)
    job = fake.uuid4()
    _JOBS[job] = ids
    return {"id": job, "hashedQueryOnView": fake.md5()}


@router.get("/humio/api/v1/repositories/{repository}/queryjobs/{job_id}")
async def search_status(job_id: str) -> dict:
    if job_id not in _JOBS:
        raise HTTPException(404, "Query job not found")
    events = [
        {
            "@timestamp": _now() * 1000,
            "Ngsiem.event.type": "ngsiem-rule-match-event",
            "Ngsiem.indicator.id": indicator,
            "Vendor.FileName": "implant.exe",
            "Vendor.FilePath": "\\Device\\HarddiskVolume2\\Program Files\\Tool\\",
            "Vendor.GrandParentBaseFileName": "cmd.exe",
            "Vendor.aip": fake.ipv4_public(),
            "process.command_line": '"C:\\Program Files\\Tool\\implant.exe" --run',
            "process.executable": (
                "\\Device\\HarddiskVolume2\\Program Files\\Tool\\implant.exe"
            ),
            "process.hash.md5": fake.md5(),
            "process.hash.sha1": "0" * 40,
            "process.hash.sha256": fake.sha256(),
            "process.parent.name": "powershell.exe",
        }
        for indicator in _JOBS[job_id]
    ]
    return {
        "done": True,
        "cancelled": False,
        "events": events,
        "metaData": {"eventCount": len(events), "isAggregate": False},
    }


def _notification(index: int) -> dict:
    created = _now() - (index + 1) * 3600
    kind = ["typosquatting_domain", "exposed_data", "post", "reply", "file"][index]
    notification = {
        "id": f"recon-notification-{index}",
        "created_date": _iso(created, 0),
        "updated_date": _iso(created, 0),
        "rule_name": f"{kind.replace('_', ' ').title()} monitoring",
        "rule_topic": "SA_BRAND",
        "rule_priority": fake.random_element(["high", "medium", "low"]),
        "item_type": kind,
        "item_date": _iso(created - 3600, 0),
        "highlights": [f"Mention of {fake.company()} on a criminal forum"],
    }
    detail = {"notification": notification}
    if kind == "typosquatting_domain":
        domain = fake.domain_name()
        notification["typosquatting"] = {
            "unicode_format": domain,
            "punycode_format": f"xn--{domain}",
            "whois": {
                "date_created": _iso(created - 30 * DAY, 0),
                "date_updated": _iso(created - DAY, 0),
                "date_expires": _iso(created + 300 * DAY, 0),
                "name_servers": ["ns1.example.net"],
                "registrant": {"name": fake.name()},
                "registrar": {"name": fake.company()},
            },
        }
    elif kind == "exposed_data":
        notification["breach_summary"] = {
            "name": f"{fake.company()} credentials",
            "description": "Credentials harvested by an infostealer",
            "exposure_date": _iso(created - 5 * DAY, 0),
            "confidence_level": "high",
            "credentials_domains": [fake.domain_name()],
            "event_date": _iso(created - 6 * DAY, 0),
            "credential_statuses": ["Valid"],
            "files": [
                {
                    "name": "logs.zip",
                    "size": 20480,
                    "complete_data_set": True,
                    "download_urls": [fake.url()],
                }
            ],
        }
        detail["breach_details"] = {
            "items": [
                {
                    "email": fake.email(),
                    "login_id": fake.user_name(),
                    "credentials_url": fake.url(),
                    "credentials_domain": fake.domain_name(),
                    "malware_family": family,
                }
                for family in ("Redline", "unknown")
            ]
        }
    else:
        detail["details"] = {
            "created_date": _iso(created, 0),
            "updated_date": _iso(created, 0),
            "site": "forum.example.net",
            "url": fake.url(),
            "author": fake.user_name(),
            "language": "en",
            "category": "Marketplace",
            "title": fake.sentence(),
            "content": fake.paragraph(),
        }
    return detail


@router.get("/recon/queries/notifications/v1")
async def query_notifications(
    limit: int = 100,
    offset: int = 0,
    filter: str = "",  # noqa: A002
) -> dict:
    details = [_notification(i) for i in range(5)]
    since = _threshold(filter, "created_date")
    if since:
        details = [
            d
            for d in details
            if _epoch(d["notification"]["created_date"]) > _epoch(since)
        ]
    ids = [d["notification"]["id"] for d in details]
    return _page(ids, offset, limit)


@router.get("/recon/entities/notifications-detailed/v1")
async def notifications_detailed(request: Request) -> dict:
    wanted = set(request.query_params.getlist("ids"))
    details = [_notification(i) for i in range(5)]
    return _envelope([d for d in details if d["notification"]["id"] in wanted])


# IOC management: the indicators created through the API, by id
_IOCS: dict[str, dict] = {}


@router.get("/iocs/queries/indicators/v1")
async def search_iocs(filter: str = "") -> dict:  # noqa: A002
    value = re.search(r'value:"([^"]*)"', filter)
    ids = [
        ioc_id
        for ioc_id, ioc in _IOCS.items()
        if value and ioc["value"] == value.group(1)
    ]
    return _envelope(ids)


@router.post("/iocs/entities/indicators/v1", status_code=201)
async def create_iocs(request: Request) -> dict:
    created = []
    for indicator in (await request.json()).get("indicators", []):
        ioc = {
            **indicator,
            "id": fake.sha256(),
            "created_by": "staticfire",
            "created_on": _iso(_now(), 3),
            "modified_on": _iso(_now(), 3),
        }
        _IOCS[ioc["id"]] = ioc
        created.append(ioc)
    return _envelope(created)


@router.patch("/iocs/entities/indicators/v1")
async def update_iocs(request: Request) -> dict:
    updated = []
    for indicator in (await request.json()).get("indicators", []):
        ioc = _IOCS.get(indicator.get("id"))
        if ioc is not None:
            ioc.update(indicator)
            updated.append(ioc)
    return _envelope(updated)


@router.delete("/iocs/entities/indicators/v1")
async def delete_iocs(request: Request) -> dict:
    ids = request.query_params.getlist("ids")
    for ioc_id in ids:
        _IOCS.pop(ioc_id, None)
    return _envelope(ids)
