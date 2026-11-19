"""Microsoft Graph (graph.microsoft.com) for the connectors reading a Microsoft 365
mailbox (email-intel-microsoft), with room for the routes of other Graph connectors
(Defender, Sentinel, Graph security...): add them to this module under ``/v1.0``.

The Graph Python SDK sends ``/v1.0//users/...`` (a doubled slash Graph accepts): the
routes are declared both ways.

Tokens come from ``microsoft_identity``. The routes below answer what the Graph SDKs
expect: ``@odata.type`` discriminators, ``@odata.nextLink`` paging and base64
``contentBytes``. The prefix is the one of the OpenAEV routes of ``app/main.py``
(sendMail, Teams messages, security alerts), which therefore answer the real host too:
they are not duplicated here.
"""

import base64
import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Query

from app.fake import fake

HOSTS = ["graph.microsoft.com"]
router = APIRouter(prefix="/microsoft-graph", tags=["Microsoft Graph"])

GRAPH = "https://graph.microsoft.com/v1.0"
PAGES = 2
MESSAGES_PER_PAGE = 2
# attachment id -> its detail, for the attachments of the messages served
ATTACHMENTS: dict[str, dict] = {}


def graph_date(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def file_attachment(name: str, mime: str, content: bytes, moment: datetime) -> dict:
    attachment = {
        "@odata.type": "#microsoft.graph.fileAttachment",
        "id": "AAMkAD" + uuid.uuid4().hex,
        "name": name,
        "contentType": mime,
        "size": len(content),
        "isInline": False,
        "lastModifiedDateTime": graph_date(moment),
    }
    ATTACHMENTS[attachment["id"]] = {
        **attachment,
        "contentBytes": base64.b64encode(content).decode(),
    }
    return attachment


def message(moment: datetime) -> dict:
    """A threat intelligence email with a PDF, a CSV and an image attachment."""
    sender = fake.company_email()
    iocs = "\n".join(f"{fake.domain_name()},{fake.ipv4_public()}" for _ in range(4))
    return {
        "@odata.etag": f'W/"{uuid.uuid4().hex}"',
        "id": "AAMkAD" + uuid.uuid4().hex,
        "receivedDateTime": graph_date(moment),
        "subject": f"Threat advisory: {fake.malware_family()} campaign",
        "hasAttachments": True,
        "from": {"emailAddress": {"name": fake.company(), "address": sender}},
        "body": {
            "contentType": "html",
            "content": f"<html><body><p>{fake.paragraph()}</p></body></html>",
        },
        "attachments": [
            file_attachment(
                "advisory.pdf",
                "application/pdf",
                b"%PDF-1.4 " + fake.binary(64),
                moment,
            ),
            file_attachment(
                "iocs.csv", "text/csv", f"domain,ip\n{iocs}".encode(), moment
            ),
            file_attachment("banner.png", "image/png", fake.binary(32), moment),
        ],
    }


@router.get("/v1.0/users/{user_id}/mailFolders")
@router.get("/v1.0//users/{user_id}/mailFolders")
async def mail_folders(user_id: str, filter: str = Query("", alias="$filter")) -> dict:
    """The folder named in a ``displayName eq '...'`` filter."""
    name = filter.split("'")[1] if "'" in filter else "Inbox"
    return {
        "@odata.context": f"{GRAPH}/$metadata#users('{user_id}')/mailFolders",
        "value": [{"id": "AAMkAD" + uuid.uuid4().hex, "displayName": name}],
    }


@router.get("/v1.0/users/{user_id}/mailFolders/{folder_id}/messages")
@router.get("/v1.0//users/{user_id}/mailFolders/{folder_id}/messages")
async def messages(
    user_id: str,
    folder_id: str,
    skiptoken: int = Query(0, alias="$skiptoken"),
) -> dict:
    """Pages of recent messages with their attachments listed (without content)."""
    page = skiptoken + 1
    now = datetime.now(UTC)
    value = [
        message(now - timedelta(days=page, hours=3 * index))
        for index in range(MESSAGES_PER_PAGE)
    ]
    answer = {
        "@odata.context": f"{GRAPH}/$metadata#users('{user_id}')/mailFolders/messages",
        "value": value,
    }
    if page < PAGES:
        link = f"{GRAPH}/users/{user_id}/mailFolders/{folder_id}/messages"
        answer["@odata.nextLink"] = f"{link}?%24skiptoken={page}&%24top=50"
    return answer


@router.get(
    "/v1.0/users/{user_id}/mailFolders/{folder_id}/messages/{message_id}"
    "/attachments/{attachment_id}"
)
@router.get(
    "/v1.0//users/{user_id}/mailFolders/{folder_id}/messages/{message_id}"
    "/attachments/{attachment_id}"
)
async def attachment(user_id: str, attachment_id: str) -> dict:
    """An attachment with its content."""
    found = ATTACHMENTS[attachment_id]
    return {
        "@odata.context": f"{GRAPH}/$metadata#users('{user_id}')/attachments/$entity",
        **found,
    }
