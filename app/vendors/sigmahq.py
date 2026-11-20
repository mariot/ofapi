"""SigmaHQ: the latest release of ``SigmaHQ/sigma`` with its rule packages, read by the
OpenCTI sigmahq connector through the GitHub fake (``GITHUB_REPOS``)."""

import io
import uuid
import zipfile
from datetime import UTC, datetime

from app.fake import fake
from app.vendors.github import Repo

PACKAGES = [
    "sigma_all_rules",
    "sigma_core++",
    "sigma_core+",
    "sigma_core",
    "sigma_emerging_threats_addon",
]


def _rule(tags: list[str]) -> str:
    """A Sigma rule: titles and ids change on every call, so does the indicator."""
    title = f"Suspicious {fake.word()} activity {uuid.uuid4().hex[:8]}"
    tag_lines = "".join(f"    - {tag}\n" for tag in tags)
    return (
        f"title: {title}\n"
        f"id: {uuid.uuid4()}\n"
        "status: test\n"
        f"description: Detects {fake.sentence(nb_words=6).rstrip('.').lower()}\n"
        "references:\n"
        f"    - https://{fake.domain_name()}/blog\n"
        "author: Staticfire\n"
        f"date: {datetime.now(UTC).strftime('%Y-%m-%d')}\n"
        f"tags:\n{tag_lines}"
        "logsource:\n"
        "    category: process_creation\n"
        "    product: windows\n"
        "detection:\n"
        "    selection:\n"
        f"        Image|endswith: '\\{fake.word()}.exe'\n"
        f"        CommandLine|contains: '{fake.word()}'\n"
        "    condition: selection\n"
        "falsepositives:\n"
        "    - Unknown\n"
        "level: high\n"
    )


def _package() -> bytes:
    """A rule package: rules by technique, by CVE and without tags."""
    rules = {
        "rules/windows/process_creation/proc_creation_win_one.yml": _rule(
            ["attack.execution", "attack.t1059.001"]
        ),
        "rules/windows/process_creation/proc_creation_win_two.yml": _rule(
            ["attack.credential-access", "attack.t1003"]
        ),
        "rules-emerging-threats/2024/Exploits/cve_exploit.yml": _rule(
            ["attack.initial-access", "attack.t1190", "cve.2024.3400"]
        ),
        "rules/windows/process_creation/proc_creation_win_three.yml": _rule([]),
    }
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("README.md", "Sigma rules\n")
        for name, content in rules.items():
            archive.writestr(name, content)
    return buffer.getvalue()


def _repo() -> Repo:
    return Repo(
        files={"README.md": b"# Sigma\n"},
        branch="master",
        tag=f"r{datetime.now(UTC).strftime('%Y-%m-%d')}",
        description="Main Sigma Rule Repository",
        assets={f"{name}.zip": _package() for name in PACKAGES},
    )


GITHUB_REPOS = {"SigmaHQ/sigma": _repo}
