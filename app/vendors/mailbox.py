"""A mailbox of realistic emails for the connectors reading mail over IMAP
(email-intel-imap and email-cases-importer).

IMAP is not HTTP: staticfire serves the IMAP protocol locally and loads the messages
from here, as raw RFC 822 texts, each time a client selects the mailbox.
"""

import io
import zipfile
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage
from email.utils import format_datetime, make_msgid

from fastapi import APIRouter

from app.fake import fake

router = APIRouter(prefix="/mailbox", tags=["Mailbox"])

ALERTS = "CERT Alerts <alerts@example.com>"
OTHER = "Threat Desk <desk@vendor.example.org>"


def pdf(text: str) -> bytes:
    stream = f"BT /F1 12 Tf 72 720 Td ({text}) Tj ET"
    objects = [
        "<< /Type /Catalog /Pages 2 0 R >>",
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R"
        " /Resources << /Font << /F1 5 0 R >> >> >>",
        f"<< /Length {len(stream)} >>\nstream\n{stream}\nendstream",
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    out = "%PDF-1.4\n"
    offsets = []
    for number, body in enumerate(objects, 1):
        offsets.append(len(out))
        out += f"{number} 0 obj\n{body}\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n"
    out += "".join(f"{offset:010d} 00000 n \n" for offset in offsets)
    size = len(objects) + 1
    out += f"trailer\n<< /Size {size} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n"
    return out.encode()


def iocs_csv() -> bytes:
    rows = ["type,value"]
    rows += [f"ipv4-addr,{fake.ipv4_public()}" for _ in range(3)]
    rows += [f"domain-name,{fake.domain_name()}" for _ in range(3)]
    rows += [f"sha256,{fake.sha256()}"]
    return "\n".join(rows).encode()


def iocs_zip() -> bytes:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as archive:
        archive.writestr("iocs.csv", iocs_csv())
    return out.getvalue()


def mail(
    sender: str,
    subject: str,
    body: str,
    sent: datetime,
    html: str | None = None,
    attachments: tuple[tuple[str, str, bytes], ...] = (),
    reply_to: str | None = None,
) -> EmailMessage:
    message = EmailMessage()
    message["Message-ID"] = make_msgid(domain="example.com")
    message["Date"] = format_datetime(sent)
    message["From"] = sender
    message["To"] = "SOC <soc@staticfire.test>"
    message["Subject"] = subject
    if reply_to:
        message["In-Reply-To"] = reply_to
        message["References"] = reply_to
    message.set_content(body)
    if html:
        message.add_alternative(html, subtype="html")
    for name, mime, content in attachments:
        main, sub = mime.split("/")
        message.add_attachment(
            content, maintype=main, subtype=sub, filename=name, disposition="attachment"
        )
    return message


@router.get("/messages")
async def messages() -> dict:
    """The mailbox, oldest first: an incident thread, a digest with a zip and its
    password, a message from another sender with an unsupported attachment, and one too
    old to import."""
    now = datetime.now(UTC).replace(microsecond=0)
    host = f"FIN-WS-{fake.random_int(10, 99)}"
    ticket = f"IR-{fake.random_int(1000, 9999)}"
    incident = mail(
        ALERTS,
        f"Incident {ticket}: suspected ransomware on {host}",
        f"Hello,\n\nWe observed {fake.malware_family()} activity on {host}.\n"
        f"C2: {fake.domain_name()} ({fake.ipv4_public()})\n\nRegards,\nCERT",
        now - timedelta(days=3),
        html=f"<p>We observed activity on <b>{host}</b>.</p><p>{fake.sentence()}</p>",
        attachments=(
            ("incident-report.pdf", "application/pdf", pdf(f"Incident {ticket}")),
            ("iocs.csv", "text/csv", iocs_csv()),
        ),
    )
    reply = mail(
        ALERTS,
        f"Re: Incident {ticket}: suspected ransomware on {host}",
        f"Update: {host} is isolated.\n\n{fake.paragraph()}",
        now - timedelta(days=2),
        reply_to=incident["Message-ID"],
    )
    digest = mail(
        ALERTS,
        f"Weekly threat digest {now.isocalendar().week}",
        "Indicators are attached.\n---BEGIN PASSWORD---\nstaticfire-pass\n"
        "---END PASSWORD---\n",
        now - timedelta(days=1),
        attachments=(("iocs.zip", "application/zip", iocs_zip()),),
    )
    other = mail(
        OTHER,
        f"New campaign targeting {fake.industry_sector()}",
        f"{fake.paragraph(nb_sentences=5)}\n",
        now - timedelta(hours=8),
        attachments=(
            ("notes.txt", "text/plain", fake.paragraph().encode()),
            ("diagram.png", "image/png", b"\x89PNG\r\n\x1a\n" + bytes(32)),
        ),
    )
    old = mail(
        ALERTS,
        "Annual awareness report",
        fake.paragraph(),
        now - timedelta(days=90),
    )
    ordered = [old, incident, reply, digest, other]
    return {
        "messages": [
            {
                "uid": number,
                "raw": message.as_string(policy=message.policy.clone(linesep="\r\n")),
            }
            for number, message in enumerate(ordered, 1)
        ]
    }
