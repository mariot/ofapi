"""The Nuclei templates repository (github.com/projectdiscovery/nuclei-templates): its
``cves.json`` index, which the OpenAEV nuclei injector reads at startup to keep one
injector contract per CVE template.

The repository is served by the GitHub fake (``GITHUB_REPOS``): the injector reads
``raw.githubusercontent.com/projectdiscovery/nuclei-templates/refs/heads/main/cves.json``.
The index is JSON lines, one per template (``ID``, ``Info`` with name, severity,
description and CVSS, ``file_path``), as the real one; three well-known CVEs with
descriptions from a seeded Faker.
"""

import json

from faker import Faker
from faker_cti import CtiProvider

from app.vendors.github import Repo

_faker = Faker()
_faker.add_provider(CtiProvider)
_faker.seed_instance(4228)

TEMPLATES = [
    ("CVE-2021-44228", "Apache Log4j2 Remote Code Injection", "critical", "10.0"),
    ("CVE-2023-46604", "Apache ActiveMQ Unauthenticated RCE", "critical", "9.8"),
    ("CVE-2024-3400", "PAN-OS GlobalProtect Command Injection", "critical", "10.0"),
]


def _line(cve: str, name: str, severity: str, score: str) -> str:
    year = cve.split("-")[1]
    return json.dumps(
        {
            "ID": cve,
            "Info": {
                "Name": name,
                "Severity": severity,
                "Description": _faker.sentence(nb_words=14),
                "Classification": {"CVSSScore": score},
            },
            "file_path": f"http/cves/{year}/{cve}.yaml",
        },
        separators=(",", ":"),
    )


def _repo() -> Repo:
    index = "\n".join(_line(*template) for template in TEMPLATES) + "\n"
    return Repo(
        files={"cves.json": index.encode()},
        branch="main",
        description="Community curated list of templates for the nuclei engine.",
    )


GITHUB_REPOS = {"projectdiscovery/nuclei-templates": _repo}
