"""OpenCTI datasets (GitHub repository OpenCTI-Platform/datasets): the sectors,
geography and companies STIX bundles, read by the OpenCTI "opencti" connector.

The repository is served by the GitHub fake (``GITHUB_REPOS``); the router only reports
what the repository holds.
"""

import json
import uuid

from fastapi import APIRouter

from app.vendors.github import Repo

router = APIRouter(prefix="/opencti-datasets", tags=["OpenCTI datasets"])

NAMESPACE = uuid.UUID("5d5c8d6e-3b0b-4b53-9c53-0d1f2a6b7c10")
NOW = "2024-06-01T00:00:00.000Z"
TLP_CLEAR = "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
AUTHOR = "identity--6a0b4a0e-4a6a-5d3b-8d0f-7d3c6e0a1b11"


def _id(kind: str, name: str) -> str:
    return f"{kind}--{uuid.uuid5(NAMESPACE, kind + name)}"


def _common(kind: str, name: str, **extra) -> dict:
    return {
        "type": kind,
        "spec_version": "2.1",
        "id": _id(kind, name),
        "created": NOW,
        "modified": NOW,
        "created_by_ref": AUTHOR,
        "object_marking_refs": [TLP_CLEAR],
        "name": name,
        **extra,
    }


def _relationship(kind: str, source: dict, target: dict) -> dict:
    return {
        "type": "relationship",
        "spec_version": "2.1",
        "id": _id("relationship", f"{kind}{source['id']}{target['id']}"),
        "created": NOW,
        "modified": NOW,
        "created_by_ref": AUTHOR,
        "object_marking_refs": [TLP_CLEAR],
        "relationship_type": kind,
        "source_ref": source["id"],
        "target_ref": target["id"],
    }


def _bundle(objects: list[dict]) -> bytes:
    """The header objects every dataset starts with: the TLP marking and the author."""
    marking = {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": TLP_CLEAR,
        "created": "2017-01-20T00:00:00.000Z",
        "definition_type": "tlp",
        "name": "TLP:CLEAR",
        "definition": {"tlp": "clear"},
    }
    author = {
        "type": "identity",
        "spec_version": "2.1",
        "id": AUTHOR,
        "created": NOW,
        "modified": NOW,
        "name": "OpenCTI",
        "identity_class": "organization",
        "description": "OpenCTI datasets maintained by Filigran.",
    }
    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid5(NAMESPACE, 'bundle' + objects[0]['name'])}",
        "objects": [marking, author, *objects],
    }
    return json.dumps(bundle, indent=2).encode()


def _sectors() -> bytes:
    def sector(name: str, description: str, **extra) -> dict:
        return _common(
            "identity",
            name,
            identity_class="class",
            description=description,
            x_opencti_type="Sector",
            **extra,
        )

    energy = sector("Energy", "Energy production and distribution.")
    finance = sector("Finance", "Banks, insurers and financial markets.")
    health = sector("Healthcare", "Hospitals and care providers.")
    subs = [
        (sector("Electricity", "Power generation."), energy),
        (
            sector("Oil and gas", "Hydrocarbons.", x_opencti_aliases=["Petroleum"]),
            energy,
        ),
        (sector("Banking", "Retail and investment banking."), finance),
    ]
    objects = [energy, finance, health]
    for child, parent in subs:
        objects += [child, _relationship("part-of", child, parent)]
    return _bundle(objects)


def _geography() -> bytes:
    def place(name: str, kind: str, **extra) -> dict:
        return _common("location", name, x_opencti_location_type=kind, **extra)

    europe = place("Europe", "Region", region="europe")
    western = place("Western Europe", "Region", region="western-europe")
    france = place("France", "Country", country="FR", x_opencti_aliases=["FRA"])
    germany = place("Germany", "Country", country="DE", x_opencti_aliases=["DEU"])
    objects = [europe, western, france, germany]
    objects.append(_relationship("located-at", western, europe))
    for country in (france, germany):
        objects.append(_relationship("located-at", country, western))
    return _bundle(objects)


def _companies() -> bytes:
    objects = [
        _common(
            "identity",
            name,
            identity_class="organization",
            description=f"{name}, a company.",
            x_opencti_organization_type="vendor",
        )
        for name in ("Contoso Security", "Fabrikam Networks", "Northwind Traders")
    ]
    return _bundle(objects)


def _repo() -> Repo:
    files = {
        "data/sectors.json": _sectors(),
        "data/geography.json": _geography(),
        "data/companies.json": _companies(),
    }
    return Repo(files, branch="master", description="OpenCTI datasets")


GITHUB_REPOS = {"OpenCTI-Platform/datasets": _repo}


@router.get("/files")
async def files() -> list[str]:
    """The dataset files the GitHub fake serves."""
    return sorted(_repo().files)
