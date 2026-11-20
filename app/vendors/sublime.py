"""Sublime Security: flagged email message groups, read by the OpenCTI sublime
connector."""

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, HTTPException

from app.fake import fake

HOSTS = ["platform.sublime.security"]
router = APIRouter(prefix="/sublime", tags=["Sublime"])

# group id -> verdict: the listing hands out these, the detail answers for any id
GROUPS: dict[str, str] = {}


def _time() -> str:
    moment = datetime.now(UTC) - timedelta(minutes=fake.random_int(5, 200))
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond:06d}Z"


@router.get("/v1/messages/groups")
async def list_groups() -> dict:
    """The canonical ids of the flagged groups of the period: four malicious, one
    benign (filtered out by the connector's verdicts)."""
    listed = {fake.uuid4(): verdict for verdict in ["malicious"] * 4 + ["benign"]}
    GROUPS.update(listed)
    return {"all_group_canonical_ids": list(listed), "count": len(listed)}


@router.get("/v1/messages/groups/{group_id}")
async def group(group_id: str) -> dict:
    """A message group: its previews and the message data model of its first email."""
    verdict = GROUPS.get(group_id)
    if verdict is None:
        raise HTTPException(status_code=404)
    sender = fake.email()
    recipients = [fake.email() for _ in range(2)]
    created = _time()
    return {
        "id": group_id,
        "attack_score_verdict": verdict,
        "subjects": [fake.sentence(nb_words=5)],
        "first_created_at": created,
        "last_created_at": created,
        "flagged_rules": [
            {"rule_meta": {"name": "Link: Credential phishing landing page"}},
            {"rule_meta": {"name": "Attachment: Macro with suspicious content"}},
        ],
        "previews": [
            {
                "sender_email_address": sender,
                "recipients": recipients,
                "attachment_sha256s": [fake.sha256()],
            }
        ],
        "data_model": {
            "sender": {"email": {"email": sender, "domain": {"domain": "mail.test"}}},
            "recipients": {
                "to": [{"email": {"email": address}} for address in recipients]
            },
            "headers": {
                "domains": [{"domain": fake.domain_name()} for _ in range(2)],
                "ips": [{"ip": fake.ipv4_public()}],
            },
            "body": {
                "plain": {"raw": fake.paragraph()},
                "links": [
                    {"href_url": {"url": fake.url(), "scheme": "https"}},
                    {"href_url": {"url": fake.url(), "scheme": "https"}},
                ],
            },
            "attachments": [
                {
                    "file_name": "invoice.docm",
                    "sha256": fake.sha256(),
                    "size": fake.random_int(2000, 90000),
                    "content_type": "application/vnd.ms-word.document.macroEnabled.12",
                }
            ],
        },
    }
