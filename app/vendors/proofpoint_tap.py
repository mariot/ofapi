"""Proofpoint TAP API v2: campaigns and SIEM events (proofpoint-tap connector).

Campaign details reuse the factories of app/api/proofpoint_tap.py (the older fake
under /proofpoint-tap), here answered on the real host with dates in the import window.
"""

from dataclasses import asdict
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter

from app.api.proofpoint_tap import CampaignDetailFactory, CampaignFactory
from app.api.utils import remove_private_attributes
from app.fake import fake

HOSTS = ["tap-api-v2.proofpoint.com"]
router = APIRouter(prefix="/proofpoint-tap-v2", tags=["Proofpoint TAP v2"])


def _iso(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _recent() -> datetime:
    return datetime.now(UTC) - timedelta(minutes=fake.random_int(5, 600))


@router.get("/v2/campaign/ids")
async def campaign_ids(interval: str = "") -> dict:  # noqa: ARG001
    """The campaigns updated during the interval."""
    campaigns = CampaignFactory.create_batch(2)
    return {
        "campaigns": [
            {**remove_private_attributes(asdict(c)), "lastUpdatedAt": _iso(_recent())}
            for c in campaigns
        ]
    }


@router.get("/v2/campaign/{campaign_id}")
async def campaign_details(campaign_id: str) -> dict:
    """A campaign with its threats, actors, malware, techniques, families and brands."""
    details = remove_private_attributes(
        asdict(CampaignDetailFactory.create(id=campaign_id))
    )
    details["startDate"] = _iso(_recent())
    for member in details["campaignMembers"]:
        member["threatTime"] = _iso(_recent())
    details["notable"] = True
    details["families"] = [{"id": fake.uuid4(), "name": fake.malware_family()}]
    details["brands"] = [{"id": fake.uuid4(), "name": fake.company()}]
    return details


def _threat(classification: str = "malware") -> dict:
    return {
        "actors": [],
        "detectionType": "Sandbox",
        "campaignID": fake.uuid4(),
        "classification": classification,
        "threat": fake.url(),
        "threatID": fake.sha256(),
        "threatStatus": "active",
        "threatTime": _iso(_recent()),
        "threatType": "attachment",
        "threatUrl": f"https://threatinsight.proofpoint.com/threat/{fake.sha256()}",
    }


def _message(moment: datetime) -> dict:
    recipient = fake.email()
    return {
        "ccAddresses": [fake.email()],
        "cluster": "staticfire_hosted",
        "completelyRewritten": "true",
        "fromAddress": [fake.email()],
        "GUID": fake.sha256()[:40],
        "headerFrom": f'"{fake.name()}" <{fake.email()}>',
        "id": fake.uuid4(),
        "impostorScore": 0,
        "malwareScore": 100,
        "messageID": f"<{fake.uuid4()}@mail.example.org>",
        "messageParts": [
            {
                "contentType": "application/pdf",
                "disposition": "attached",
                "filename": fake.file_name(extension="pdf"),
                "md5": fake.md5(),
                "oContentType": "application/pdf",
                "sandboxStatus": "threat",
                "sha256": fake.sha256(),
            }
        ],
        "messageSize": fake.random_int(2000, 90000),
        "messageTime": _iso(moment),
        "modulesRun": ["spam", "sandbox", "urldefense"],
        "phishScore": 40,
        "policyRoutes": ["default_inbound"],
        "QID": fake.bothify("????######").lower(),
        "quarantineFolder": "Attachment Defense",
        "quarantineRule": "module.sandbox.threat",
        "recipient": [recipient],
        "replyToAddress": [],
        "sender": fake.email(),
        "senderIP": fake.ipv4_public(),
        "spamScore": 10,
        "subject": fake.sentence(),
        "threatsInfoMap": [_threat()],
        "toAddresses": [recipient],
        "xmailer": "Microsoft Outlook 16.0",
    }


def _click(moment: datetime) -> dict:
    return {
        "campaignId": fake.uuid4(),
        "classification": "phish",
        "clickIP": fake.ipv4_public(),
        "clickTime": _iso(moment),
        "GUID": fake.sha256()[:40],
        "messageID": f"<{fake.uuid4()}@mail.example.org>",
        "recipient": fake.email(),
        "sender": fake.email(),
        "senderIP": fake.ipv4_public(),
        "threatID": fake.sha256(),
        "threatTime": _iso(moment),
        "threatURL": f"https://threatinsight.proofpoint.com/threat/{fake.sha256()}",
        "threatStatus": "active",
        "url": fake.url(),
        "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    }


def _siem(interval: str, with_clicks: bool = True) -> dict:
    """Events of one half-hour window: only the last one (up to now) holds some."""
    end = datetime.fromisoformat(interval.split("/")[1])
    recent = datetime.now(UTC) - end < timedelta(minutes=2)
    moment = end - timedelta(minutes=5)
    return {
        "queryEndTime": _iso(end),
        "messagesDelivered": [_message(moment)] if recent else [],
        "messagesBlocked": [_message(moment)] if recent else [],
        "clicksPermitted": [_click(moment)] if recent and with_clicks else [],
        "clicksBlocked": [_click(moment)] if recent and with_clicks else [],
    }


@router.get("/v2/siem/all")
@router.get("/v2/siem/issues")
async def siem_all(interval: str) -> dict:
    """Delivered and blocked messages and permitted and blocked clicks."""
    return _siem(interval)


@router.get("/v2/siem/messages/blocked")
@router.get("/v2/siem/messages/delivered")
@router.get("/v2/siem/clicks/blocked")
@router.get("/v2/siem/clicks/permitted")
async def siem_one(interval: str) -> dict:
    """The same window, whatever the kind of events asked."""
    return _siem(interval)
