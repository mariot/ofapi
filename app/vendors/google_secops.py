"""Google SecOps (Chronicle API v1alpha, ``<region>-chronicle.googleapis.com``): the
instance, the legacy rule alerts search and the entities import, read by the OpenCTI
google-secops-siem-incidents (import) and google-secops-siem (stream) connectors.

The incidents connector's aiohttp client ignores the proxy variables, so it is
pointed at ofapi with its region set to ``127.0.0.1:<port>/google-secops/r``. The URL
it builds is then ``https://127.0.0.1:<port>/google-secops/r-chronicle.googleapis.com/
v1alpha/...`` and its location path holds slashes. The service account token endpoint is
``google_identity``."""

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Request

from app.fake import fake

HOSTS = ["chronicle.googleapis.com", "*-chronicle.googleapis.com"]
router = APIRouter(prefix="/google-secops", tags=["Google SecOps"])

INSTANCE = "/v1alpha/projects/{project}/locations/{location}/instances/{instance}"
# the same API reached with the region prefix in the path
DIRECT = "/r-chronicle.googleapis.com" + INSTANCE.replace(
    "{location}", "{location:path}"
)


def _stamp(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _outcome(name: str, **values) -> dict:
    return {"name": name, **values}


def _alert(rule_type: str, index: int) -> dict:
    detected = datetime.now(UTC) - timedelta(hours=1 + index)
    outcomes = [
        _outcome("risk_score", int64Val=str(fake.random_int(10, 95))),
        _outcome("principal_ip", stringSeq={"stringVals": [fake.ipv4_public()]}),
        _outcome("principal_hostname", stringVal=fake.domain_name()),
        _outcome("target_url", stringSeq={"stringVals": [fake.url()]}),
        _outcome("principal_user_userid", stringSeq={"stringVals": [fake.user_name()]}),
        _outcome(
            "principal_user_email_addresses", stringSeq={"stringVals": [fake.email()]}
        ),
        _outcome("principal_process_file_full_path", stringVal="C:\\Temp\\payload.exe"),
        _outcome("principal_process_file_sha256", stringVal=fake.sha256()),
        _outcome("mitre_attack_technique_id", stringSeq={"stringVals": ["T1059"]}),
    ]
    return {
        "id": f"de_{fake.uuid4()}",
        "fields": [
            {"name": "hostname", "stringVal": fake.domain_name()},
            {"name": "src_ip", "stringVal": fake.ipv4_public()},
            {"name": "user_email", "stringVal": fake.email()},
        ],
        "timeWindow": {
            "startTime": _stamp(detected - timedelta(minutes=10)),
            "endTime": _stamp(detected),
        },
        "ruleType": rule_type,
        "detectionTimestamp": _stamp(detected),
        "commitTimestamp": _stamp(detected + timedelta(seconds=5)),
        "alertingType": "ALERTING",
        "outcomes": outcomes,
        "resultEvents": {},
        "resultEntityEvents": {},
    }


def _rule(name: str, severity: str, priority: str, rule_type: str) -> dict:
    return {
        "ruleMetadata": {
            "ruleId": f"ru_{fake.uuid4()}",
            "properties": {
                "name": name,
                "text": f'rule {name} {{ events: $e.metadata.event_type = "NETWORK" }}',
                "metadata": {
                    "severity": severity,
                    "priority": priority,
                    "description": "Suspicious process network activity",
                    "tags": "staticfire,execution",
                    "mitre_attach_url": "https://attack.mitre.org/techniques/T1059/",
                },
            },
        },
        "alerts": [_alert(rule_type, index) for index in range(2)],
    }


async def _alerts() -> dict:
    return {
        "ruleAlerts": [
            _rule("suspicious_powershell", "HIGH", "HIGH", "SINGLE_EVENT"),
            _rule("beaconing_to_rare_domain", "MEDIUM", "LOW", "MULTI_EVENT"),
        ],
        "tooManyAlerts": False,
    }


def _instance(project: str, location: str, instance: str) -> dict:
    return {
        "name": f"projects/{project}/locations/{location}/instances/{instance}",
        "state": "ACTIVE",
        "displayName": "Staticfire SecOps",
        "secopsUrls": [f"https://{instance}.backstory.chronicle.security"],
    }


@router.get(INSTANCE + "/legacy:legacySearchRulesAlerts")
async def legacy_search_rules_alerts() -> dict:
    """The alerts of two rules (one single-event, one multi-event), on one page."""
    return await _alerts()


@router.get(INSTANCE)
async def get_instance(project: str, location: str, instance: str) -> dict:
    return _instance(project, location, instance)


@router.post(INSTANCE + "/entities:import")
async def import_entities(request: Request) -> dict:
    """Accepts the inline entities (the journal keeps what was sent)."""
    await request.body()
    return {}


@router.get(DIRECT + "/legacy:legacySearchRulesAlerts")
async def direct_legacy_search_rules_alerts() -> dict:
    return await _alerts()


@router.get(DIRECT)
async def direct_get_instance(project: str, location: str, instance: str) -> dict:
    return _instance(project, location, instance)
