"""Files to import into a platform, built with faker-cti, for file import connectors.

A test fetches a file here and uploads it to the platform; the connector under test then
parses it. Every call gives new values, so repeated imports create new knowledge.
"""

import zlib

from fastapi import APIRouter, Response

from app.fake import fake

router = APIRouter(prefix="/fixtures", tags=["Fixtures"])


def _bundle() -> dict:
    author = fake.stix_identity(identity_class="organization")
    intrusion_set = fake.stix_intrusion_set()
    malware = fake.stix_malware()
    attack_pattern = fake.stix_attack_pattern()
    indicator = fake.stix_indicator(stix_type="ipv4-addr")
    observable = fake.stix_observable(stix_type="domain-name")
    relationships = [
        fake.stix_relationship(intrusion_set["id"], malware["id"], "uses"),
        fake.stix_relationship(malware["id"], attack_pattern["id"], "uses"),
        fake.stix_relationship(indicator["id"], malware["id"], "indicates"),
    ]
    objects = [
        intrusion_set,
        malware,
        attack_pattern,
        indicator,
        observable,
        *relationships,
    ]
    for obj in objects:
        obj["created_by_ref"] = author["id"]
    report = fake.stix_report(object_refs=[o["id"] for o in objects])
    report["created_by_ref"] = author["id"]
    return fake.stix_bundle(objects=[author, *objects, report])


@router.get("/stix-bundle.json")
async def stix_bundle() -> dict:
    """A report on an intrusion set, its malware, technique and indicator."""
    return _bundle()


def _report_text() -> str:
    ip, domain = fake.ipv4_public(), fake.domain_name()
    sha256 = fake.sha256()
    return (
        f"Threat report: {fake.intrusion_set()} targets the "
        f"{fake.industry_sector()} sector\n\n"
        f"The group used {fake.malware_family()} delivered from {domain} and the "
        f"command and control server {ip}. The dropper (SHA-256 {sha256}) exploits "
        f"{fake.cve_id()} and relies on {fake.mitre_attack_technique_id()}.\n"
        f"Contact: {fake.email()}  URL: https://{domain}/payload.bin\n"
    )


@router.get("/report.txt")
async def report_text() -> Response:
    """A short threat report in plain text: indicators, a CVE, a technique id."""
    return Response(_report_text(), media_type="text/plain")


def _pdf(text: str) -> bytes:
    """A one-page PDF showing ``text`` (Helvetica, one line per text line)."""
    escaped = [
        line.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
        for line in text.splitlines()
    ]
    lines = "".join(f"({line}) Tj T* " for line in escaped)
    stream = zlib.compress(f"BT /F1 9 Tf 12 TL 40 800 Td {lines}ET".encode("latin-1"))
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
        b"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length %d /Filter /FlateDecode >>\nstream\n" % len(stream)
        + stream
        + b"\nendstream",
    ]
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for number, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % number + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1)
    out += b"".join(b"%010d 00000 n \n" % offset for offset in offsets)
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (
        len(objects) + 1,
        xref,
    )
    return bytes(out)


@router.get("/report.pdf")
async def report_pdf() -> Response:
    """The plain text report as a PDF."""
    return Response(_pdf(_report_text()), media_type="application/pdf")


@router.get("/rules.yar")
async def yara_rules() -> Response:
    """Two YARA rules matching a malware family's strings."""
    rules = []
    for _ in range(2):
        name = fake.malware_family().replace(" ", "_").replace("-", "_")
        mutex = fake.mutex_name().replace("\\", "\\\\")  # escaped for a YARA string
        rules.append(
            f"rule {name}_{fake.random_int(100, 999)}\n{{\n"
            f'    meta:\n        description = "{fake.sentence()}"\n'
            f'        author = "{fake.company()}"\n'
            f'    strings:\n        $a = "{mutex}"\n'
            f"        $b = {{ {' '.join(fake.hexify('^^') for _ in range(8))} }}\n"
            f"    condition:\n        any of them\n}}\n"
        )
    return Response("\n".join(rules), media_type="text/plain")


@router.get("/misp-event.json")
async def misp_event() -> dict:
    """A MISP event export with network and file attributes and a galaxy cluster."""
    ip, domain = fake.ipv4_public(), fake.domain_name()
    group = fake.intrusion_set()
    return {
        "Event": {
            "id": str(fake.random_int(1, 99999)),
            "uuid": fake.uuid4(),
            "info": f"{fake.intrusion_set()} campaign",
            "date": fake.date_this_year().isoformat(),
            "timestamp": str(int(fake.date_time_this_year().timestamp())),
            "threat_level_id": "2",
            "analysis": "2",
            "distribution": "1",
            "published": True,
            "Orgc": {"name": fake.company(), "uuid": fake.uuid4()},
            "Tag": [{"name": "tlp:green"}],
            "Attribute": [
                {
                    "uuid": fake.uuid4(),
                    "type": kind,
                    "category": category,
                    "value": value,
                    "to_ids": True,
                    "comment": "",
                    "timestamp": str(int(fake.date_time_this_year().timestamp())),
                }
                for kind, category, value in [
                    ("ip-dst", "Network activity", ip),
                    ("domain", "Network activity", domain),
                    ("sha256", "Payload delivery", fake.sha256()),
                ]
            ],
            "Object": [],
            "Galaxy": [
                {
                    "namespace": "mitre-attack",
                    "type": "mitre-attack-pattern",
                    "name": "Attack Pattern",
                    "GalaxyCluster": [
                        {
                            "value": "Phishing - T1566",
                            "description": "Adversaries may send phishing messages.",
                            "meta": {"external_id": ["T1566"]},
                        }
                    ],
                },
                {
                    "namespace": "mitre-attack",
                    "type": "mitre-intrusion-set",
                    "name": "Intrusion Set",
                    "GalaxyCluster": [
                        {
                            "value": f"{group} - {fake.mitre_attack_group_id()}",
                            "description": fake.sentence(),
                            "meta": {"synonyms": [group]},
                        }
                    ],
                },
            ],
        }
    }


@router.get("/navigator-layer.json")
async def navigator_layer() -> dict:
    """An ATT&CK Navigator layer scoring a few techniques."""
    return {
        "name": f"{fake.intrusion_set()} TTPs",
        "versions": {"attack": "16", "navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": fake.sentence(),
        "techniques": [
            {"techniqueID": technique, "score": 1, "color": "#ff6666", "enabled": True}
            for technique in {fake.mitre_attack_technique_id() for _ in range(4)}
        ],
    }
