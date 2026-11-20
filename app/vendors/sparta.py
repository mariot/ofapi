"""Aerospace SPARTA: the space attack research and tactic analysis STIX bundle
(sparta connector)."""

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter

from app.fake import fake

HOSTS = ["sparta.aerospace.org"]
router = APIRouter(prefix="/sparta", tags=["SPARTA"])

TACTICS = [
    ("REC", "Reconnaissance"),
    ("RD", "Resource Development"),
    ("IA", "Initial Access"),
    ("EX", "Execution"),
    ("PER", "Persistence"),
]


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _common(kind: str, **fields) -> dict:
    now = _now()
    return {
        "type": kind,
        "spec_version": "2.1",
        "id": f"{kind}--{uuid.uuid4()}",
        "created": now,
        "modified": now,
        **fields,
    }


def _reference(external_id: str) -> list[dict]:
    return [
        {
            "source_name": "sparta",
            "external_id": external_id,
            "url": f"https://sparta.aerospace.org/technique/{external_id}",
        }
    ]


def _bundle() -> dict:
    objects = []
    techniques = []
    for prefix, phase in TACTICS:
        technique = _common(
            "attack-pattern",
            name=f"{phase}: {fake.sentence(nb_words=3).rstrip('.')}",
            description=fake.paragraph(),
            kill_chain_phases=[{"kill_chain_name": "sparta", "phase_name": phase}],
            external_references=_reference(f"{prefix}-0001"),
            x_sparta_is_subtechnique="False",
        )
        sub = _common(
            "attack-pattern",
            name=f"{phase}: {fake.sentence(nb_words=3).rstrip('.')}",
            description=fake.paragraph(),
            kill_chain_phases=[{"kill_chain_name": "sparta", "phase_name": phase}],
            external_references=_reference(f"{prefix}-0001.01"),
            x_sparta_is_subtechnique="True",
        )
        techniques += [technique, sub]
        # SPARTA types the link of a sub-technique to its parent as related-to
        objects += [
            technique,
            sub,
            _common(
                "relationship",
                relationship_type="related-to",
                source_ref=sub["id"],
                target_ref=technique["id"],
            ),
        ]
    for number in range(1, 4):
        countermeasure = _common(
            "course-of-action",
            name=f"Countermeasure {number}: {fake.sentence(nb_words=3).rstrip('.')}",
            description=fake.paragraph(),
            external_references=_reference(f"CM{number:04d}"),
        )
        objects += [
            countermeasure,
            _common(
                "relationship",
                relationship_type="related-to",
                source_ref=countermeasure["id"],
                target_ref=techniques[number]["id"],
            ),
        ]
    for number in range(1, 3):
        pattern = f"[x-sparta:indicator_id = 'IND-{number:04d}-{uuid.uuid4().hex[:6]}']"
        indicator = _common(
            "indicator",
            name=f"IND-{number:04d}",
            description=fake.sentence(),
            pattern=pattern,
            pattern_type="stix",
            valid_from=_now(),
        )
        objects += [
            indicator,
            _common(
                "relationship",
                relationship_type="indicates",
                source_ref=indicator["id"],
                target_ref=techniques[0]["id"],
            ),
        ]
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}


@router.get("/download/STIX")
async def download_stix() -> dict:
    """The SPARTA matrix as one STIX bundle."""
    return _bundle()
