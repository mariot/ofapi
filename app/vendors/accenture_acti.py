"""Accenture ACTI: AWS Cognito (SRP login, JWKS), the ACTI collections API and the S3
bucket of report images, read by the OpenCTI accenture-acti connector.

Cognito tokens are RS256 JWTs the client verifies against the pool's JWKS, so this
module signs them with a throwaway RSA key (pure Python: no crypto dependency).
"""

import base64
import hashlib
import json
import secrets
import time
from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException, Request, Response

from app.fake import fake

REGION = "eu-west-1"
POOL_ID = "eu-west-1_StaticFire"
BUCKET = "staticfire-acti"
HOSTS = [
    f"cognito-idp.{REGION}.amazonaws.com",
    f"{BUCKET}.s3.{REGION}.amazonaws.com",
    "api.intel.accenture.com",
]
router = APIRouter(prefix="/accenture-acti", tags=["Accenture ACTI"])

KID = "staticfire-acti-key"
ISSUER = f"https://cognito-idp.{REGION}.amazonaws.com/{POOL_ID}"
# SHA-256 DigestInfo prefix of an RSASSA-PKCS1-v1_5 signature (RFC 8017, section 9.2)
SHA256_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")
IMAGE_HASH = hashlib.sha256(b"staticfire acti image").hexdigest()
# A 1x1 PNG
PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kg"
    "AAAABJRU5ErkJggg=="
)

_key: dict[str, int] = {}


def _is_prime(n: int, rounds: int = 24) -> bool:
    if n < 4:
        return n in (2, 3)
    if n % 2 == 0:
        return False
    d, r = n - 1, 0
    while d % 2 == 0:
        d, r = d // 2, r + 1
    for _ in range(rounds):
        x = pow(secrets.randbelow(n - 3) + 2, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _prime(bits: int) -> int:
    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if _is_prime(candidate):
            return candidate


def _rsa_key() -> dict[str, int]:
    """A 2048-bit RSA key, generated on first use."""
    if not _key:
        while True:
            p, q = _prime(1024), _prime(1024)
            phi = (p - 1) * (q - 1)
            if p != q and phi % 65537:
                break
        _key.update(n=p * q, e=65537, d=pow(65537, -1, phi))
    return _key


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _int_bytes(value: int) -> bytes:
    return value.to_bytes((value.bit_length() + 7) // 8, "big")


def _jwt(claims: dict) -> str:
    key = _rsa_key()
    header = {"alg": "RS256", "kid": KID, "typ": "JWT"}
    signing_input = (
        _b64url(json.dumps(header).encode())
        + "."
        + _b64url(json.dumps(claims).encode())
    )
    size = (key["n"].bit_length() + 7) // 8
    digest_info = SHA256_PREFIX + hashlib.sha256(signing_input.encode()).digest()
    padded = (
        b"\x00\x01" + b"\xff" * (size - len(digest_info) - 3) + b"\x00" + digest_info
    )
    signature = pow(int.from_bytes(padded, "big"), key["d"], key["n"])
    return signing_input + "." + _b64url(signature.to_bytes(size, "big"))


@router.get(f"/{POOL_ID}/.well-known/jwks.json")
async def jwks() -> dict:
    key = _rsa_key()
    return {
        "keys": [
            {
                "kty": "RSA",
                "alg": "RS256",
                "use": "sig",
                "kid": KID,
                "n": _b64url(_int_bytes(key["n"])),
                "e": _b64url(_int_bytes(key["e"])),
            }
        ]
    }


@router.post("/")
async def cognito(request: Request) -> Response:
    """The Cognito IDP API: the SRP exchange of pycognito, then the tokens."""
    action = request.headers.get("X-Amz-Target", "").rsplit(".", 1)[-1]
    body = await request.json()
    if action == "InitiateAuth":
        payload = {
            "ChallengeName": "PASSWORD_VERIFIER",
            "ChallengeParameters": {
                "SALT": secrets.token_hex(16),
                "SECRET_BLOCK": base64.b64encode(secrets.token_bytes(64)).decode(),
                "SRP_B": secrets.token_hex(128),
                "USERNAME": body["AuthParameters"]["USERNAME"],
                "USER_ID_FOR_SRP": body["AuthParameters"]["USERNAME"],
            },
        }
    elif action == "RespondToAuthChallenge":
        now = int(time.time())
        username = body["ChallengeResponses"]["USERNAME"]
        common = {"sub": fake.uuid4(), "iss": ISSUER, "iat": now, "exp": now + 3600}
        payload = {
            "ChallengeParameters": {},
            "AuthenticationResult": {
                "AccessToken": _jwt(
                    {
                        **common,
                        "token_use": "access",
                        "client_id": body["ClientId"],
                        "username": username,
                    }
                ),
                "IdToken": _jwt(
                    {
                        **common,
                        "token_use": "id",
                        "aud": body["ClientId"],
                        "cognito:username": username,
                    }
                ),
                "RefreshToken": secrets.token_urlsafe(48),
                "ExpiresIn": 3600,
                "TokenType": "Bearer",
            },
        }
    else:
        raise HTTPException(400, f"Unsupported action {action}")
    return Response(json.dumps(payload), media_type="application/x-amz-json-1.1")


@router.get("/document-images/{name}")
async def s3_image(name: str) -> Response:
    """The S3 bucket: only the PNG of the report exists (the connector tries each
    extension and takes the first object found)."""
    if name != f"{IMAGE_HASH}.png":
        error = (
            '<?xml version="1.0" encoding="UTF-8"?><Error><Code>NoSuchKey</Code>'
            f"<Message>The specified key does not exist.</Message><Key>{name}</Key>"
            "</Error>"
        )
        return Response(error, status_code=404, media_type="application/xml")
    return Response(PNG, media_type="image/png")


def _stamp() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _sdo(kind: str, **fields) -> dict:
    return {
        "type": kind,
        "spec_version": "2.1",
        "id": f"{kind}--{fake.uuid4()}",
        "created": _stamp(),
        "modified": _stamp(),
        **fields,
    }


def _relationship(source: dict, kind: str, target: dict) -> dict:
    return _sdo(
        "relationship",
        relationship_type=kind,
        source_ref=source["id"],
        target_ref=target["id"],
    )


@router.get("/collections/acti/collections")
async def collections(start_date: str = "", end_date: str = "") -> dict:
    """A STIX bundle of the objects modified in the window: a report on a threat actor,
    its malware, an indicator and a location, with images referenced by hash and as
    data URIs."""
    actor = _sdo(
        "threat-actor",
        name=fake.intrusion_set(),
        threat_actor_types=["crime-syndicate"],
        roles=["agent"],
        sophistication="advanced",
        personal_motivations=["financial-gain"],
    )
    malware = _sdo("malware", name=fake.malware_family(), is_family=True)
    domain = fake.domain_name()
    indicator = _sdo(
        "indicator",
        name=domain,
        pattern=f"[domain-name:value = '{domain}']",
        pattern_type="stix",
        valid_from=_stamp(),
        indicator_types=["malicious-activity"],
    )
    location = _sdo("location", name="Germany", country="DE")
    report = _sdo(
        "report",
        name=f"{actor['name']} targets European retailers",
        created=start_date or _stamp(),
        modified=end_date or _stamp(),
        published=start_date or _stamp(),
        report_types=["threat-report"],
        description=(
            f"<p>{fake.paragraph()}</p>"
            f'<img src="/api/v1/axon/files/by/sha256/{IMAGE_HASH}">'
            f'<img src="data:image/png;base64,{base64.b64encode(PNG).decode()}">'
        ),
        labels=["France", "ransomware"],
        x_severity="high",
        x_threat_type=["ransomware"],
        object_refs=[actor["id"], malware["id"], indicator["id"], location["id"]],
    )
    return {
        "type": "bundle",
        "id": f"bundle--{fake.uuid4()}",
        "objects": [
            report,
            actor,
            malware,
            indicator,
            location,
            _relationship(report, "related-to", actor),
            _relationship(actor, "uses", malware),
            _relationship(actor, "located-at", location),
            _relationship(indicator, "indicates", malware),
        ],
    }
