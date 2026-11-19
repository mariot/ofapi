"""HarfangLab console: alerts, threats and threat intelligence rule sources.

Read by the OpenCTI harfanglab-incidents connector, written by harfanglab-intel."""

import re
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlencode

from fastapi import APIRouter, HTTPException, Query, Request

from app.fake import fake

HOSTS = ["tenant.hurukai.io"]
router = APIRouter(prefix="/harfanglab", tags=["HarfangLab"])

TI = "/api/data/threat_intelligence"
PAGE_SIZE = 5
ALERT_COUNT = 8
THREAT_COUNT = 3
IOC_TYPES = {
    "hash",
    "filename",
    "filepath",
    "ip_src",
    "ip_dst",
    "ip_both",
    "domain_name",
    "url",
}
TECHNIQUE_TAGS = ["attack.t1059.001", "attack.t1566", "attack.t1047"]

# Rules a stream connector wrote, per kind; the id of each source list by kind
_sources: dict[str, list[dict]] = {"IOCSource": [], "SigmaSource": [], "YaraSource": []}
_rules: dict[str, dict[str, dict]] = {"IOCRule": {}, "SigmaRule": {}, "YaraFile": {}}
# Rules the console holds because an alert was raised on them
_alert_iocs: dict[str, dict] = {}
_alert_sigma: dict[str, dict] = {}
_alert_yara: dict[str, dict] = {}
_threats: dict[str, dict] = {}
_levels = ["critical", "high", "medium", "low"]


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _time(start: datetime, end: datetime) -> datetime:
    return fake.date_time_between(start_date=start, end_date=end, tzinfo=UTC)


def _iso(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _agent() -> dict:
    return {
        "agentid": fake.uuid4(),
        "hostname": f"{fake.word()}-{fake.random_int(10, 99)}".upper(),
        "ostype": fake.random_element(["windows", "linux"]),
        "osproducttype": fake.random_element(["workstation", "server"]),
    }


def _process() -> dict:
    return {
        "usersid": f"S-1-5-21-{fake.random_int(1000, 9999)}-{fake.random_int(10, 99)}",
        "username": fake.user_name(),
        "current_directory": "C:\\Users\\Public\\Downloads",
        "process_name": f"{fake.word()}.exe",
        "hashes": {"sha256": fake.sha256(), "sha1": fake.sha1(), "md5": fake.md5()},
    }


def _ioc_alert(kind: str, process: dict) -> dict:
    """An alert raised by an IOC rule, registered under the value the message ends
    with (``<type>=<value>``)."""
    values = {
        "hash": process["hashes"]["sha256"],
        "filename": process["process_name"],
        "ip_dst": fake.ipv4_public(),
        "domain_name": fake.domain_name(),
        "url": fake.url(),
    }
    value = values[kind]
    created = _iso(datetime.now(UTC) - timedelta(days=30))
    _alert_iocs[value] = {
        "id": fake.uuid4(),
        "type": kind,
        "value": value,
        "creation_date": created,
        "last_update": created,
    }
    return {"msg": f"IOC match {kind}={value}", "rule_name": None, "alert_type": "ioc"}


def _sigma_alert() -> dict:
    name = f"proc_creation_win_{fake.word()}_{fake.word()}"
    rule_name = f"{name} (Sigma rule)"
    created = _iso(datetime.now(UTC) - timedelta(days=60))
    _alert_sigma[rule_name] = {
        "id": fake.uuid4(),
        "name": f"{name}.yml",
        "rule_name": rule_name,
        "content": (
            f"title: {name}\nid: {fake.uuid4()}\nstatus: stable\nlogsource:\n"
            "  category: process_creation\n  product: windows\ndetection:\n"
            "  selection:\n    Image|endswith: '\\powershell.exe'\n"
            "  condition: selection\nlevel: high\n"
        ),
        "creation_date": created,
        "last_update": created,
    }
    return {
        "msg": f"Sigma detection {name}",
        "rule_name": rule_name,
        "alert_type": "sigma",
    }


def _yara_alert() -> dict:
    name = f"{fake.word()}_{fake.word()}"
    created = _iso(datetime.now(UTC) - timedelta(days=60))
    _alert_yara[f"{name}.yar"] = {
        "id": fake.uuid4(),
        "name": f"{name}.yar",
        "content": (f'rule {name} {{ strings: $a = "{fake.word()}" condition: $a }}'),
        "rule_names": [name],
        "rule_technique_tags": fake.random_elements(
            TECHNIQUE_TAGS, length=2, unique=True
        ),
        "creation_date": created,
        "last_update": created,
    }
    return {
        "msg": f"YARA match {name}",
        "rule_name": f"{name}:{name}.yar",
        "alert_type": "yara",
    }


ALERT_KINDS = ["hash", "filename", "ip_dst", "domain_name", "url", "sigma", "yara"]


def _alerts(count_: int, start: datetime, wanted: set[str]) -> list[dict]:
    """Alerts of the types asked (all by default), cycling through the kinds."""
    kinds = [
        k
        for k in ALERT_KINDS
        if not wanted or (k if k in ("sigma", "yara") else "ioc") in wanted
    ]
    times = sorted(_time(start, datetime.now(UTC)) for _ in range(count_))
    alerts = []
    for index, when in enumerate(times):
        process = _process()
        kind = kinds[index % len(kinds)]
        if kind == "sigma":
            detection = _sigma_alert()
        elif kind == "yara":
            detection = _yara_alert()
        else:
            detection = _ioc_alert(kind, process)
        alerts.append(
            {
                "id": fake.uuid4(),
                "alert_unique_id": fake.uuid4(),
                "status": fake.random_element(["new", "investigating"]),
                "log_type": fake.random_element(["process", "network", "filesystem"]),
                "level": fake.random_element(_levels),
                "maturity": "stable",
                "process": process,
                "agent": _agent(),
                "alert_time": _iso(when),
                "last_update": _iso(when + timedelta(minutes=5)),
                **detection,
            }
        )
    return alerts


def _page(request: Request, items: list[dict], offset: int) -> dict:
    """A Django-REST style page; ``next`` is a path with the next page's query."""
    page = items[offset : offset + PAGE_SIZE]
    following = offset + PAGE_SIZE
    query = [(k, v) for k, v in request.query_params.multi_items() if k != "offset"]
    return {
        "count": len(items),
        "next": (
            f"{request.url.path.removeprefix('/harfanglab')}?"
            f"{urlencode(query + [('offset', following)])}"
            if following < len(items)
            else None
        ),
        "previous": None,
        "results": page,
    }


_alert_pages: dict[str, list[dict]] = {}


@router.get("/api/data/alert/alert/Alert")
async def alerts(
    request: Request,
    alert_type: str = "",
    from_: str | None = Query(None, alias="from"),
    threat_key: str | None = None,
    offset: int = 0,
) -> dict:
    """Alerts oldest first, five per page; a threat's alerts with ``threat_key``."""
    wanted = {t.strip() for t in alert_type.split(",") if t.strip()}
    key = urlencode(
        [(k, v) for k, v in request.query_params.multi_items() if k != "offset"]
    )
    if offset == 0 or key not in _alert_pages:
        start = (
            datetime.fromisoformat(from_)
            if from_
            else datetime.now(UTC) - timedelta(days=3)
        )
        start = max(start, datetime.now(UTC) - timedelta(days=3))
        _alert_pages[key] = _alerts(
            THREAT_COUNT if threat_key else ALERT_COUNT, start, wanted
        )
    return _page(request, _alert_pages[key], offset)


@router.get("/api/data/alert/alert/Threat")
async def threats(
    request: Request, from_: str | None = Query(None, alias="from"), offset: int = 0
) -> dict:
    """Threats grouping alerts, oldest first."""
    if offset == 0:
        start = (
            datetime.fromisoformat(from_)
            if from_
            else datetime.now(UTC) - timedelta(days=3)
        )
        start = max(start, datetime.now(UTC) - timedelta(days=3))
        times = sorted(_time(start, datetime.now(UTC)) for _ in range(THREAT_COUNT))
        _threats.clear()
        for when in times:
            agent = _agent()
            threat_id = fake.uuid4()
            _threats[threat_id] = {
                "id": threat_id,
                "slug": f"{fake.word()}-{fake.word()}-{fake.random_int(100, 999)}",
                "status": fake.random_element(["new", "investigating"]),
                "level": fake.random_element(_levels),
                "top_agents": [
                    {
                        "agent_id": agent["agentid"],
                        "agent_hostname": agent["hostname"],
                        "agent_ostype": agent["ostype"],
                        "agent_osproducttype": agent["osproducttype"],
                        "alert_count": fake.random_int(1, 20),
                    }
                ],
                "top_impacted_users": [
                    {
                        "user_sid": f"S-1-5-21-{fake.random_int(1000, 9999)}",
                        "user_name": fake.user_name(),
                    }
                ],
                "first_seen": _iso(when),
                "last_seen": _iso(when + timedelta(minutes=30)),
                "creation_date": _iso(when),
            }
    return _page(request, list(_threats.values()), offset)


@router.get("/api/data/alert/alert/Threat/{threat_id}/note")
async def threat_note(threat_id: str) -> dict:  # noqa: ARG001
    """The analyst note of a threat."""
    when = _now()
    return {
        "title": fake.sentence(nb_words=4),
        "content": fake.paragraph(),
        "creation_date": when,
        "last_update": when,
    }


def _listing(results: list[dict]) -> dict:
    return {"count": len(results), "next": None, "previous": None, "results": results}


def _find(kind: str, field: str, value: str, registry: dict[str, dict]) -> list[dict]:
    stored = [r for r in _rules[kind].values() if r.get(field) == value]
    known = registry.get(value)
    return stored or ([known] if known else [])


@router.get(f"{TI}/IOCRule")
@router.get(f"{TI}/IOCRule/")
async def get_ioc_rules(
    source_id: str | None = None,  # noqa: ARG001
    type: str | None = None,  # noqa: A002
    value__exact: str = "",
) -> dict:
    """IOC rules by exact value, from a source list or raised in an alert."""
    rules = _find("IOCRule", "value", value__exact, _alert_iocs)
    return _listing([r for r in rules if type is None or r["type"] == type])


@router.get(f"{TI}/SigmaRule")
@router.get(f"{TI}/SigmaRule/")
async def get_sigma_rules(
    source_id: str | None = None,  # noqa: ARG001
    name__exact: str | None = None,
    rule_name__exact: str | None = None,
) -> dict:
    """Sigma rules by file name (``name``) or by rule name."""
    if rule_name__exact:
        return _listing(_find("SigmaRule", "rule_name", rule_name__exact, _alert_sigma))
    stored = [r for r in _rules["SigmaRule"].values() if r["name"] == name__exact]
    return _listing(stored)


@router.get(f"{TI}/YaraFile")
@router.get(f"{TI}/YaraFile/")
async def get_yara_files(
    source_id: str | None = None,  # noqa: ARG001
    name__exact: str = "",
) -> dict:
    """YARA files by name, from a source list or raised in an alert."""
    return _listing(_find("YaraFile", "name", name__exact, _alert_yara))


@router.post(f"{TI}/IOCRule/")
async def post_ioc_rule(request: Request) -> dict:
    """Creates an IOC rule (a duplicated type and value is refused)."""
    body = await request.json()
    if body.get("type") not in IOC_TYPES:
        raise HTTPException(
            400, {"type": [f'"{body.get("type")}" is not a valid choice.']}
        )
    key = f"{body['type']}:{body['value']}"
    if key in _rules["IOCRule"]:
        raise HTTPException(400, "IOC rule with this type and value already exists.")
    rule = {"id": fake.uuid4(), "creation_date": _now(), "last_update": _now(), **body}
    _rules["IOCRule"][key] = rule
    return rule


def _file_rule(kind: str, body: dict[str, Any]) -> dict:
    """Sigma rules and YARA files are created through an upload: the answer lists the
    file stored (``filename``) under ``status``."""
    stem = re.sub(r"\.(yml|yar)$", "", body["name"])
    ext = "yml" if kind == "SigmaRule" else "yar"
    rule = {
        "id": fake.uuid4(),
        "name": body["name"],
        "filename": f"{stem}.{ext}",
        "rule_name": body["name"],
        "creation_date": _now(),
        "last_update": _now(),
        **{k: v for k, v in body.items() if k != "name"},
    }
    _rules[kind][rule["id"]] = rule
    return {"status": [rule]}


@router.post(f"{TI}/SigmaRule/")
async def post_sigma_rule(request: Request) -> dict:
    """Uploads a Sigma rule."""
    return _file_rule("SigmaRule", await request.json())


@router.post(f"{TI}/YaraFile/")
async def post_yara_file(request: Request) -> dict:
    """Uploads a YARA file."""
    return _file_rule("YaraFile", await request.json())


def _kind_of(kind: str) -> dict[str, dict]:
    if kind not in _rules:
        raise HTTPException(404)
    return _rules[kind]


@router.patch(f"{TI}/{{kind}}/{{rule_id}}")
async def patch_rule(kind: str, rule_id: str, request: Request) -> dict:
    """Updates a rule of a source list."""
    body = await request.json()
    rules = _kind_of(kind)
    rule = next((r for r in rules.values() if r["id"] == rule_id), None)
    if rule is None:
        raise HTTPException(404)
    rule.update(body, last_update=_now())
    return rule


@router.delete(f"{TI}/{{kind}}/{{rule_id}}")
async def delete_rule(kind: str, rule_id: str) -> None:
    """Deletes a rule of a source list."""
    rules = _kind_of(kind)
    for key, rule in list(rules.items()):
        if rule["id"] == rule_id:
            del rules[key]


@router.get(f"{TI}/{{source_kind}}")
async def get_source(source_kind: str, name__exact: str = "") -> dict:
    """The source list of a kind (IOCSource, SigmaSource, YaraSource) by name."""
    if source_kind not in _sources:
        raise HTTPException(404)
    return _listing([s for s in _sources[source_kind] if s["name"] == name__exact])


@router.post(f"{TI}/{{source_kind}}")
async def post_source(source_kind: str, request: Request) -> dict:
    """Creates a source list."""
    body = await request.json()
    if source_kind not in _sources:
        raise HTTPException(404)
    source = {"id": fake.uuid4(), "creation_date": _now(), **body}
    _sources[source_kind].append(source)
    return source
