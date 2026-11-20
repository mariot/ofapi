"""The OpenAEV scenarios repository (github.com/OpenAEV-Platform/scenarios), followed by
the OpenAEV scenarios collector: a channel's pointer (``edge.json`` on the ``channels``
branch) names a release and the SHA-256 of its manifest; the release's assets are the
manifest, one import archive per scenario and one file per payload version.

The repositories are served by the GitHub fake (``GITHUB_REPOS``): the pointer through
``contents`` (raw media type), the release through ``releases/tags/<release>`` and its
assets through ``releases/assets/<id>`` (redirected to the storage host).

* ``OpenAEV-Platform/scenarios``: a consistent release (two scenarios, a payload
  version), every hash right;
* ``OpenAEV-Platform/scenarios-tampered``: the same release, one archive changed after
  the manifest was written (its size kept), which a collector must refuse.

Scenario names, descriptions and payload commands come from a seeded Faker (with the CTI
providers), so the releases are the same run after run.
"""

import hashlib
import io
import json
import uuid
import zipfile

from faker import Faker
from faker_cti import CtiProvider

from app.vendors.github import Repo

RELEASE = "1.261119.0"
APPROVER = "staticfire-releaser"

_faker = Faker()
_faker.add_provider(CtiProvider)
_faker.seed_instance(2611)


def _uuid() -> str:
    return str(uuid.UUID(int=_faker.random.getrandbits(128), version=4))


def _archive(external_id: str, version: str) -> bytes:
    """An import archive as the platform exports a scenario: a JSON document, zipped."""
    actor = _faker.threat_actor() if hasattr(_faker, "threat_actor") else "APT29"
    scenario = {
        "export_version": 1,
        "scenario_information": {
            "scenario_id": external_id,
            "scenario_external_reference": external_id,
            "scenario_name": f"{actor} intrusion emulation",
            "scenario_description": _faker.paragraph(nb_sentences=3),
            "scenario_category": "attack-scenario",
            "scenario_main_focus": "endpoint-protection",
            "scenario_severity": "high",
            "scenario_version": version,
        },
        "scenario_injects": [],
        "scenario_tags": [],
    }
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            f"{external_id}.json", json.dumps(scenario, indent=2, sort_keys=True)
        )
    return buffer.getvalue()


def _listed(name: str, data: bytes) -> dict:
    return {"name": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def _release(repository: str, tamper: bool) -> Repo:
    items, assets = [], {}
    for version in ("1.0.0", "1.2.0"):
        external_id = _uuid()
        name = f"{external_id}-{version}.zip"
        data = _archive(external_id, version)
        assets[name] = data
        items.append(
            {
                "external_id": external_id,
                "version": version,
                "archive": _listed(name, data),
            }
        )
    payload = {
        "payload_name": "Process discovery (PowerShell)",
        "payload_type": "Command",
        "command_executor": "psh",
        "command_content": "Get-Process | Select-Object -First 20",
        "payload_platforms": ["Windows"],
    }
    payload_name = "process-discovery-ps-1.0.0.json"
    assets[payload_name] = json.dumps(payload, indent=2).encode()
    manifest = {
        "schema_version": 1,
        "repository": repository,
        "channel": "edge",
        "release": RELEASE,
        "release_approver": APPROVER,
        "items": items,
        "payloads": [
            {
                "payload": "process-discovery-ps",
                "version": "1.0.0",
                "file": _listed(payload_name, assets[payload_name]),
            }
        ],
    }
    manifest_bytes = json.dumps(manifest, indent=2).encode()
    assets["manifest.json"] = manifest_bytes
    if tamper:
        # The first archive changed after the manifest was written, its size kept
        first = items[0]["archive"]["name"]
        data = bytearray(assets[first])
        data[-1] ^= 0xFF
        assets[first] = bytes(data)
    pointer = {
        "schema_version": 1,
        "repository": repository,
        "channel": "edge",
        "release": RELEASE,
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
    }
    return Repo(
        files={"edge.json": json.dumps(pointer, indent=2).encode()},
        branch="main",
        tag=RELEASE,
        description="OpenAEV scenarios catalogue",
        assets=assets,
    )


GITHUB_REPOS = {
    "OpenAEV-Platform/scenarios": lambda: _release("OpenAEV-Platform/scenarios", False),
    "OpenAEV-Platform/scenarios-tampered": lambda: _release(
        "OpenAEV-Platform/scenarios-tampered", True
    ),
}
