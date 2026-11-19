"""ESET Threat Intelligence: the TAXII 1.1 service (eset import connector) and
the APT report download (eset-enrichment connector).

The ETI report API (``eti_api``: urllib3 on a hardcoded host) ignores proxies, so the
connector's APT report import cannot be served and must be disabled.
"""

import json
import re
import uuid
from datetime import UTC, datetime, timedelta
from xml.sax.saxutils import escape, quoteattr

from fastapi import APIRouter, Request, Response

from app.fake import fake

HOSTS = ["eti.eset.com"]
router = APIRouter(prefix="/eset", tags=["ESET"])

NS = "http://taxii.mitre.org/messages/taxii_xml_binding-1.1"
HEADERS = {
    "X-TAXII-Content-Type": "urn:taxii.mitre.org:message:xml:1.1",
    "X-TAXII-Protocol": "urn:taxii.mitre.org:protocol:https:1.0",
    "X-TAXII-Services": "urn:taxii.mitre.org:services:1.1",
}


def xml(body: str) -> Response:
    return Response(content=body, media_type="application/xml", headers=HEADERS)


def now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def attribute(body: str, name: str) -> str:
    found = re.search(rf'\b{name}="([^"]*)"', body)
    return found.group(1) if found else ""


@router.post("/taxiiservice/discovery")
async def discovery(request: Request) -> Response:
    """The poll service, advertised at its public address."""
    message_id = attribute((await request.body()).decode(), "message_id")
    return xml(
        f'<taxii_11:Discovery_Response xmlns:taxii_11="{NS}"'
        f' message_id="{uuid.uuid4()}" in_response_to="{message_id}">'
        '<taxii_11:Service_Instance service_type="POLL"'
        ' service_version="urn:taxii.mitre.org:services:1.1" available="true">'
        "<taxii_11:Protocol_Binding>urn:taxii.mitre.org:protocol:https:1.0"
        "</taxii_11:Protocol_Binding>"
        "<taxii_11:Address>https://eti.eset.com/taxiiservice/poll</taxii_11:Address>"
        "<taxii_11:Message_Binding>urn:taxii.mitre.org:message:xml:1.1"
        "</taxii_11:Message_Binding>"
        "</taxii_11:Service_Instance>"
        "</taxii_11:Discovery_Response>"
    )


def indicator(pattern: str, created: str, labels: list[str]) -> dict:
    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": f"indicator--{uuid.uuid4()}",
        "created": created,
        "modified": created,
        "name": "ESET indicator",
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": created,
        "labels": labels,
    }


def bundle(collection: str, created: str) -> dict:
    """The kinds of objects ESET publishes: indicators, malware, relationships, and the
    identity "customer" and observed data the connector drops."""
    family = fake.malware_family()
    malware = {
        "type": "malware",
        "spec_version": "2.1",
        "id": f"malware--{uuid.uuid4()}",
        "created": created,
        "modified": created,
        "name": family,
        "is_family": True,
        "malware_types": ["trojan"],
    }
    customer = {
        "type": "identity",
        "spec_version": "2.1",
        "id": f"identity--{uuid.uuid4()}",
        "created": created,
        "modified": created,
        "name": "customer",
        "identity_class": "class",
    }
    patterns = {
        "ei.misp": [
            f"[file:hashes.SHA1 = '{fake.sha1()}']",
            f"[file:hashes.SHA256 = '{fake.sha256()}']",
            f"[file:hashes.MD5 = '{fake.md5()}']",
        ],
        "ei.cc": [
            f"[ipv4-addr:value = '{fake.ipv4_public()}']",
            f"[domain-name:value = '{fake.domain_name()}']",
        ],
        "ei.urls": [f"[url:value = '{fake.url()}']", f"[url:value = '{fake.url()}']"],
    }.get(collection, [f"[domain-name:value = '{fake.domain_name()}']"])
    indicators = [indicator(p, created, ["malicious-activity"]) for p in patterns]
    relationships = [
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": f"relationship--{uuid.uuid4()}",
            "created": created,
            "modified": created,
            "relationship_type": "indicates",
            "source_ref": item["id"],
            "target_ref": malware["id"],
        }
        for item in indicators
    ]
    observed = {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": f"observed-data--{uuid.uuid4()}",
        "created": created,
        "modified": created,
        "first_observed": created,
        "last_observed": created,
        "number_observed": 1,
        "object_refs": [],
    }
    targeting = {
        "type": "relationship",
        "spec_version": "2.1",
        "id": f"relationship--{uuid.uuid4()}",
        "created": created,
        "modified": created,
        "relationship_type": "targets",
        "source_ref": malware["id"],
        "target_ref": customer["id"],
    }
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": [
            malware,
            customer,
            observed,
            targeting,
            *indicators,
            *relationships,
        ],
    }


@router.post("/taxiiservice/poll")
async def poll(request: Request) -> Response:
    """One content block (a STIX bundle) for the window asked, in a single part."""
    body = (await request.body()).decode()
    collection = attribute(body, "collection_name")
    begin = re.search(r"Exclusive_Begin_Timestamp[^>]*>([^<]+)<", body)
    created = begin.group(1) if begin else now()
    created = (
        datetime.fromisoformat(created.replace("Z", "+00:00")) + timedelta(minutes=1)
    ).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    content = json.dumps(bundle(collection.split(" ")[0], created))
    return xml(
        f'<taxii_11:Poll_Response xmlns:taxii_11="{NS}" message_id="{uuid.uuid4()}"'
        f' in_response_to="{attribute(body, "message_id")}"'
        f' collection_name={quoteattr(collection)} more="false" result_part_number="1">'
        f"<taxii_11:Inclusive_End_Timestamp_Label>{now()}"
        "</taxii_11:Inclusive_End_Timestamp_Label>"
        "<taxii_11:Content_Block>"
        '<taxii_11:Content_Binding binding_id="application/stix+json;version=2.1"/>'
        f"<taxii_11:Content>{escape(content)}</taxii_11:Content>"
        f"<taxii_11:Timestamp_Label>{created}</taxii_11:Timestamp_Label>"
        "</taxii_11:Content_Block>"
        "</taxii_11:Poll_Response>"
    )


@router.get("/api/v2/apt-reports/{report_uid}/download/pdf")
async def apt_report_pdf(report_uid: str) -> Response:
    """An APT report as a PDF, behind the key|secret bearer token."""
    text = f"ESET APT report {report_uid} {fake.sentence()}"
    objects = [
        "<< /Type /Catalog /Pages 2 0 R >>",
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R"
        " /Resources << /Font << /F1 5 0 R >> >> >>",
        None,
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    stream = f"BT /F1 12 Tf 72 720 Td ({text}) Tj ET"
    objects[3] = f"<< /Length {len(stream)} >>\nstream\n{stream}\nendstream"
    pdf = "%PDF-1.4\n"
    offsets = []
    for number, body in enumerate(objects, 1):
        offsets.append(len(pdf))
        pdf += f"{number} 0 obj\n{body}\nendobj\n"
    xref = len(pdf)
    pdf += f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n"
    pdf += "".join(f"{offset:010d} 00000 n \n" for offset in offsets)
    size = len(objects) + 1
    pdf += f"trailer\n<< /Size {size} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n"
    return Response(content=pdf.encode(), media_type="application/pdf")
