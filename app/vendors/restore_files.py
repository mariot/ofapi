"""A backup directory in the format of the backup-files stream connector, for the
restore-files import connector, which reads a local directory and calls no API.

The test downloads this tree and writes it under the connector's backup path. The
older run directory holds the report and its intrusion set and malware; what they
reference (author, technique, indicator, observable) is only in the newer one, so the
connector resolves missing references across run directories.
"""

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter

from app.fake import fake

router = APIRouter(prefix="/restore-files", tags=["Restore files"])


def _file(obj: dict) -> dict:
    return {"type": "bundle", "objects": [obj]}


@router.get("/backup")
async def backup() -> dict[str, dict]:
    """The backup tree: "<run directory>/<stix id>.json" mapped to the file content."""
    author = fake.stix_identity(identity_class="organization")
    intrusion_set = fake.stix_intrusion_set()
    malware = fake.stix_malware()
    attack_pattern = fake.stix_attack_pattern()
    indicator = fake.stix_indicator(stix_type="ipv4-addr")
    observable = fake.stix_observable(stix_type="domain-name")
    older = [
        intrusion_set,
        malware,
        fake.stix_relationship(intrusion_set["id"], malware["id"], "uses"),
    ]
    newer = [
        author,
        attack_pattern,
        indicator,
        observable,
        fake.stix_relationship(malware["id"], attack_pattern["id"], "uses"),
        fake.stix_relationship(indicator["id"], malware["id"], "indicates"),
    ]
    for obj in [*older, *newer]:
        if obj["id"] != author["id"]:
            obj["created_by_ref"] = author["id"]
    report = fake.stix_report(
        object_refs=[o["id"] for o in [*older, attack_pattern, indicator]]
    )
    report["created_by_ref"] = author["id"]
    older.append(report)
    now = datetime.now(UTC).replace(second=0, microsecond=0)
    runs = {
        (now - timedelta(minutes=2)).strftime("%Y%m%dT%H%M%SZ"): older,
        (now - timedelta(minutes=1)).strftime("%Y%m%dT%H%M%SZ"): newer,
    }
    return {
        f"{run}/{obj['id']}.json": _file(obj)
        for run, objects in runs.items()
        for obj in objects
    }
