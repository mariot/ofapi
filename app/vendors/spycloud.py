"""SpyCloud Enterprise API: watchlist breach records (paged by cursor) and the breach
catalog (spycloud connector)."""

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Query

from app.fake import fake

HOSTS = ["api.spycloud.io"]
router = APIRouter(prefix="/spycloud", tags=["SpyCloud"])

SEVERITIES = [2, 5, 20, 25]


def _published() -> str:
    moment = datetime.now(UTC) - timedelta(days=fake.random_int(1, 10))
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _stealer_record(source_id: int) -> dict:
    """A malware (infostealer) record: device, network and target details."""
    return {
        "document_id": fake.uuid4(),
        "source_id": source_id,
        "spycloud_publish_date": _published(),
        "severity": 25,
        "email": fake.email(),
        "username": fake.user_name(),
        "full_name": fake.name(),
        "ip_addresses": [fake.ipv4_public(), fake.ipv4_public()],
        "user_hostname": f"DESKTOP-{fake.bothify('??#####').upper()}",
        "user_os": "Windows 10 Pro",
        "mac_address": fake.mac_address().replace(":", "").upper(),
        "infected_path": f"C:\\Users\\{fake.user_name()}\\AppData\\Temp\\svc.exe",
        "target_url": fake.url(),
        "target_domain": fake.domain_name(),
        "target_subdomain": f"login.{fake.domain_name()}",
        "user_agent": fake.user_agent(),
        "password_plaintext": fake.password(),
    }


def _breach_record(source_id: int) -> dict:
    """A plain breach record: account details only."""
    return {
        "document_id": fake.uuid4(),
        "source_id": source_id,
        "spycloud_publish_date": _published(),
        "severity": fake.random_element(SEVERITIES[:3]),
        "email": fake.email(),
        "username": fake.user_name(),
        "target_domain": fake.domain_name(),
    }


@router.get("/enterprise-v2/breach/data/watchlist")
async def watchlist(cursor: str = Query("")) -> dict:
    """Two pages of records: the first one gives a cursor, the second an empty one."""
    if cursor:
        records = [_breach_record(10001), _breach_record(10002)]
        return {"cursor": "", "hits": 4, "results": records}
    records = [_stealer_record(10003), _breach_record(10001)]
    return {"cursor": fake.sha1(), "hits": 4, "results": records}


@router.get("/enterprise-v2/breach/catalog/{catalog_id}")
async def catalog(catalog_id: int) -> dict:
    """The breach a record comes from."""
    published = datetime.now(UTC) - timedelta(days=30)
    return {
        "cursor": "",
        "hits": 1,
        "results": [
            {
                "id": catalog_id,
                "uuid": fake.uuid4(),
                "title": f"{fake.company()} Breach",
                "short_title": fake.company(),
                "description": fake.paragraph(),
                "type": "PUBLIC",
                "num_records": fake.random_int(1000, 10**6),
                "spycloud_publish_date": published.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "acquisition_date": published.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "assets": {"email": 1000, "username": 800},
                "confidence": 3,
                "breach_main_category": "breach",
                "breach_category": "database",
                "sensitive_source": False,
                "consumer_category": "other",
                "tlp": "amber",
            }
        ],
    }
