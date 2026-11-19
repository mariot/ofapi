"""Citalid: the risk intelligence center (password grant, then versioned STIX bundles),
read by the OpenCTI citalid connector. The customer sub-domain is any ``*.citalid.com``.
"""

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, HTTPException

from app.fake import fake

HOSTS = ["*.citalid.com"]
router = APIRouter(prefix="/citalid", tags=["Citalid"])

API = "/facade/risk-intelligence-center/api/v1"


def _version(days_ago: int) -> str:
    day = datetime.now(UTC) - timedelta(days=days_ago)
    return f"{day:%Y%m%d}T{fake.random_int(0, 23):02d}0000Z"


VERSIONS = [_version(3), _version(2), _version(1)]


@router.post("/auth/o/token/")
async def token() -> dict:
    return {
        "access_token": fake.pystr(30, 30),
        "token_type": "Bearer",
        "expires_in": 36000,
        "scope": "read write",
        "refresh_token": fake.pystr(30, 30),
    }


@router.get(API + "/stix-bundles/versions/")
async def versions() -> list[dict]:
    """The published versions, the date being the start of their id."""
    return [
        {"id": version, "size": fake.random_int(10_000, 99_999)} for version in VERSIONS
    ]


@router.get(API + "/stix-bundles/versions/{version_id}/download/")
async def download(version_id: str) -> dict:
    """A bundle of threats relevant to the customer."""
    if version_id not in VERSIONS:
        raise HTTPException(404, "unknown version")
    intrusion_set = fake.stix_intrusion_set()
    malware = fake.stix_malware()
    vulnerability = fake.stix_vulnerability()
    objects = [
        intrusion_set,
        malware,
        vulnerability,
        fake.stix_indicator(),
        fake.stix_relationship(intrusion_set["id"], malware["id"], "uses"),
        fake.stix_relationship(malware["id"], vulnerability["id"], "targets"),
    ]
    objects.append(
        fake.stix_report(
            object_refs=[o["id"] for o in objects], name=f"Risk scenario {version_id}"
        )
    )
    return fake.stix_bundle(objects=objects)
