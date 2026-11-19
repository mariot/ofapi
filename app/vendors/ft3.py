"""Stripe FT3 (Fraud Tactics, Techniques, and Procedures): the framework JSON files of
the stripe/ft3 repository, served by the GitHub module (ft3 connector)."""

import json

from app.vendors.github import Repo

TACTICS = [
    ("FT001", "Reconnaissance"),
    ("FT002", "Resource Development"),
    ("FT003", "Initial Access"),
    ("FT004", "Defense Evasion"),
    ("FT005", "Positioning"),
    ("FT006", "Execution"),
    ("FT007", "Monetization"),
]

# (id, name, tactics, parent id)
TECHNIQUES = [
    ("FT1001", "Acquire Stolen Card Data", "Resource Development", ""),
    ("FT1001.001", "Card Dump Purchase", "Resource Development", "FT1001"),
    ("FT1001.002", "Phished Credentials", "Resource Development", "FT1001"),
    ("FT1002", "Account Takeover", "Initial Access, Execution", ""),
    ("FT1002.001", "Credential Stuffing", "Initial Access", "FT1002"),
    ("FT1003", "Synthetic Identity", "Initial Access, Defense Evasion", ""),
    ("FT1004", "Card Testing", "Positioning", ""),
    ("FT1005", "Cash Out Through Resellers", "Monetization", ""),
]


def _tactics() -> list[dict]:
    return [
        {
            "ID": tactic_id,
            "name": name,
            "description": f"The adversary is trying to achieve: {name.lower()}.",
            "created": "01/30/2024",
            "last_modified": "6/12/25",
            "url": f"https://github.com/stripe/ft3/tree/master/tactics/{tactic_id}",
        }
        for tactic_id, name in TACTICS
    ]


def _techniques() -> list[dict]:
    return [
        {
            "id": technique_id,
            "name": name,
            "description": f"Fraud technique: {name}.",
            "tactics": tactics,
            "is_sub-technique": "TRUE" if parent else "FALSE",
            "sub-technique of": parent,
            "detection": "Monitor for velocity anomalies and mismatched identity data.",
            "created": "01/30/2024",
            "last_modified": "6/12/25",
        }
        for technique_id, name, tactics, parent in TECHNIQUES
    ]


def _repo() -> Repo:
    return Repo(
        files={
            "FT3_Tactics.json": json.dumps(_tactics()).encode(),
            "FT3_Techniques.json": json.dumps(_techniques()).encode(),
        },
        branch="master",
        description="Fraud Tactics, Techniques, and Procedures",
    )


GITHUB_REPOS = {"stripe/ft3": _repo}
