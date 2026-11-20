"""Team Cymru Scout (Pure Signal): the foundation and search endpoints, answering STIX
bundles, read by the OpenCTI team-cymru-scout and team-cymru-scout-search connectors."""

import re
import uuid
from datetime import UTC, datetime

from fastapi import APIRouter

from app.fake import fake

HOSTS = ["taxii.cymru.com"]
router = APIRouter(prefix="/team-cymru", tags=["Team Cymru"])

AS_NAMESPACE = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")
IP_QUERY = re.compile(r"\b(?:ip|comms\.ip)\s*=\s*\"?(\d{1,3}(?:\.\d{1,3}){3})")
DOMAIN_QUERY = re.compile(r"^[a-z0-9.-]+\.[a-z]{2,}$", re.IGNORECASE)


def _sco(kind: str, **fields) -> dict:
    """A cyber observable whose id derives from its main property, like a real feed."""
    key = fields.get("value") or fields.get("number") or uuid.uuid4().hex
    return {
        "type": kind,
        "spec_version": "2.1",
        "id": f"{kind}--{uuid.uuid5(AS_NAMESPACE, f'{kind}{key}')}",
        **fields,
    }


def _sdo(kind: str, stamp: str, **fields) -> dict:
    return {
        "type": kind,
        "spec_version": "2.1",
        "id": f"{kind}--{uuid.uuid4()}",
        "created": stamp,
        "modified": stamp,
        **fields,
    }


def _relationship(stamp: str, kind: str, source: dict, target: dict) -> dict:
    return _sdo(
        "relationship",
        stamp,
        relationship_type=kind,
        source_ref=source["id"],
        target_ref=target["id"],
    )


def _bundle(subject: dict) -> dict:
    """What Scout knows of an address or a domain: its network, owner, country, peers,
    a certificate, flows and an indicator, with relationships (some of them ones the
    connectors rewrite or drop)."""
    stamp = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    # a domain is known through the address it resolves to
    host = (
        subject
        if subject["type"] == "ipv4-addr"
        else _sco("ipv4-addr", value=fake.ipv4_public())
    )
    asn = fake.random_int(1000, 399999)
    system = _sco("autonomous-system", number=asn, name=f"AS{asn} {fake.company()}")
    owner = _sdo("identity", stamp, name=fake.company(), identity_class="organization")
    country = fake.country_code()
    place = _sdo(
        "location", stamp, name=fake.country(), country=country, region="europe"
    )
    peer = _sco("ipv4-addr", value=fake.ipv4_public())
    peer_domain = _sco("domain-name", value=fake.domain_name())
    junk_domain = _sco("domain-name", value=f"_dmarc.{fake.domain_name()}")
    certificate = _sco(
        "x509-certificate",
        serial_number=fake.sha1()[:20],
        issuer=f"CN={fake.domain_name()}",
        hashes={"SHA-256": fake.sha256()},
    )
    flow = _sco(
        "network-traffic",
        protocols=["tcp"],
        dst_port=fake.random_element([443, 8080, 4444]),
        src_ref=host["id"],
    )
    indicator = _sdo(
        "indicator",
        stamp,
        name=f"Scout {subject['value']}",
        pattern=f"[{subject['type']}:value = '{subject['value']}']",
        pattern_type="stix",
        valid_from=stamp,
        indicator_types=["malicious-activity"],
        labels=["scout"],
    )
    objects = [
        subject,
        *([] if host is subject else [host]),
        system,
        owner,
        place,
        peer,
        peer_domain,
        junk_domain,
        certificate,
        flow,
        indicator,
        _relationship(stamp, "belongs-to", host, system),
        _relationship(stamp, "owned-by", host, owner),
        _relationship(stamp, "located-at", host, place),
        _relationship(stamp, "communicates-with", host, peer),
        _relationship(stamp, "resolves-to", peer_domain, host),
        _relationship(stamp, "uses", host, certificate),
        _relationship(stamp, "belongs-to", certificate, system),
        _relationship(stamp, "indicates", indicator, subject),
        *(
            []
            if host is subject
            else [_relationship(stamp, "resolves-to", subject, host)]
        ),
        _relationship(stamp, "located-at", flow, place),
        _relationship(stamp, "uses", peer_domain, junk_domain),
    ]
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}


@router.get("/api/scout/ip/foundation")
async def foundation(ips: str) -> dict:
    """The STIX bundle of the requested address."""
    return _bundle(_sco("ipv4-addr", value=ips.split(",")[0]))


@router.get("/api/scout/search")
async def search(query: str) -> dict:
    """The STIX bundle of a domain, or of the address a Scout query names."""
    if DOMAIN_QUERY.match(query):
        return _bundle(_sco("domain-name", value=query))
    found = IP_QUERY.search(query)
    return _bundle(
        _sco("ipv4-addr", value=found.group(1) if found else fake.ipv4_public())
    )
