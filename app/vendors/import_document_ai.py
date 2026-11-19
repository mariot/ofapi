"""Filigran's document extraction web service (Ariane), read by the import-document-ai
connector in its legacy direct mode: a document goes in, a STIX bundle comes out."""

import uuid

from fastapi import APIRouter, Request, UploadFile
from fastapi.responses import JSONResponse

from app.fake import fake

HOSTS = ["importdoc.ariane.filigran.io"]
router = APIRouter(prefix="/import-document-ai", tags=["Import Document AI"])


# Well known techniques, which a platform with the MITRE ATT&CK data already holds
TECHNIQUES = [
    ("T1078", "Valid Accounts"),
    ("T1566", "Phishing"),
    ("T1059", "Command and Scripting Interpreter"),
]


def _obj(stix_type: str, stix_id: str | None = None, **properties) -> dict:
    now = fake.stix_timestamp()
    return {
        "type": stix_type,
        "spec_version": "2.1",
        "id": stix_id or f"{stix_type}--{uuid.uuid4()}",
        "created": now,
        "modified": now,
        **properties,
    }


def _observable(stix_type: str, **properties) -> dict:
    return {
        "type": stix_type,
        "spec_version": "2.1",
        "id": f"{stix_type}--{uuid.uuid4()}",
        **properties,
    }


def _relationship(source: dict, relationship_type: str, target: dict) -> dict:
    return _obj(
        "relationship",
        relationship_type=relationship_type,
        source_ref=source["id"],
        target_ref=target["id"],
    )


def _bundle() -> dict:
    group = _obj("intrusion-set", name=fake.intrusion_set())
    malware = _obj("malware", name=fake.malware_family(), is_family=True)
    technique_id, technique_name = fake.random_element(TECHNIQUES)
    # the service derives its ids from the content, not as OpenCTI does
    technique = _obj(
        "attack-pattern",
        f"attack-pattern--{uuid.uuid5(uuid.NAMESPACE_URL, technique_id)}",
        name=technique_name,
        x_mitre_id=technique_id,
    )
    country = _obj("location", name="France", country="FR")
    region = _obj("location", name="Europe", region="europe")
    vulnerability = _obj("vulnerability", name=fake.cve_id())
    domain = fake.domain_name()
    observables = [
        _observable("ipv4-addr", value=fake.ipv4_public()),
        # the extraction returns the indicators of a document as written in it: defanged
        _observable("domain-name", value=domain.replace(".", "[.]")),
        _observable("url", value=f"hxxps://{fake.domain_name()}/{fake.slug()}"),
        _observable("email-addr", value=fake.email().replace("@", "[at]")),
        _observable("file", hashes={"SHA-256": fake.sha256()}),
    ]
    objects = [group, malware, technique, country, region, vulnerability, *observables]
    objects += [
        _relationship(group, "uses", malware),
        _relationship(malware, "uses", technique),
        _relationship(group, "targets", country),
        _relationship(country, "located-at", region),
    ]
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}


@router.post("/stix")
async def extract_stix(request: Request, file: UploadFile) -> JSONResponse:
    """The STIX objects found in the uploaded document (licence header required)."""
    if not request.headers.get("X-OpenCTI-Certificate"):
        return JSONResponse(
            status_code=400, content={"detail": "Missing X-OpenCTI-Certificate header"}
        )
    await file.read()
    return JSONResponse(_bundle())
