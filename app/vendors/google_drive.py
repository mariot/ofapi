"""Google Drive API v3 (``www.googleapis.com/drive/v3``): a folder holding a PDF, a Word
document and a file of another type, read by the OpenCTI google-drive connector. The
service account token comes from ``google_identity``."""

import io
import zipfile

from fastapi import APIRouter, Request, Response

from app.fake import fake
from app.vendors.fixtures import _pdf, _report_text

HOSTS = ["www.googleapis.com"]
router = APIRouter(prefix="/google-drive", tags=["Google Drive"])

FOLDER_MIME = "application/vnd.google-apps.folder"
PDF_MIME = "application/pdf"
DOCX_MIME = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
FOLDER_ID = "1StaticfireFolderIdAAAAAAAAAAAAAA"
FILES = {
    "1StaticfirePdfAAAAAAAAAAAAAAAAAA": ("apt-report.pdf", PDF_MIME),
    "1StaticfireDocxAAAAAAAAAAAAAAAAA": ("incident-notes.docx", DOCX_MIME),
    "1StaticfirePngAAAAAAAAAAAAAAAAAA": ("diagram.png", "image/png"),
}


def _docx(text: str) -> bytes:
    """A minimal Word document holding ``text`` as paragraphs."""
    paragraphs = "".join(
        f"<w:p><w:r><w:t>{line}</w:t></w:r></w:p>" for line in text.splitlines()
    )
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            "[Content_Types].xml",
            '<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.'
            'openxmlformats.org/package/2006/content-types"><Default Extension="rels" '
            'ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/><Override '
            'PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-'
            'officedocument.wordprocessingml.document.main+xml"/></Types>',
        )
        archive.writestr(
            "_rels/.rels",
            '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.'
            'openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" '
            'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/'
            'officeDocument" Target="word/document.xml"/></Relationships>',
        )
        archive.writestr(
            "word/document.xml",
            '<?xml version="1.0" encoding="UTF-8"?><w:document xmlns:w="http://schemas.'
            f'openxmlformats.org/wordprocessingml/2006/main"><w:body>{paragraphs}'
            "</w:body></w:document>",
        )
    return out.getvalue()


def _content(file_id: str) -> bytes:
    _, mime = FILES[file_id]
    if mime == PDF_MIME:
        return _pdf(_report_text())
    if mime == DOCX_MIME:
        return _docx(_report_text())
    return b"\x89PNG\r\n\x1a\n" + fake.binary(length=64)


def _time(days_ago: int) -> str:
    return fake.date_time_between(f"-{days_ago}d", f"-{days_ago - 1}d").strftime(
        "%Y-%m-%dT%H:%M:%S.000Z"
    )


@router.get("/drive/v3/files")
async def list_files(q: str = "") -> dict:
    """The folder lookup by name, then the files of the folder."""
    if FOLDER_MIME in q:
        files = [{"id": FOLDER_ID, "name": "Threat reports"}]
    elif f"'{FOLDER_ID}' in parents" in q:
        files = [
            {
                "id": file_id,
                "name": name,
                "mimeType": mime,
                "createdTime": _time(6 - index),
                "modifiedTime": _time(3 - index),
            }
            for index, (file_id, (name, mime)) in enumerate(FILES.items())
        ]
    else:
        files = []
    return {"kind": "drive#fileList", "incompleteSearch": False, "files": files}


@router.get("/drive/v3/files/{file_id}")
async def get_file(file_id: str, request: Request, alt: str = "json") -> Response:
    """The media of a file (``alt=media``), in the byte range asked if any."""
    if file_id not in FILES:
        return Response(status_code=404)
    name, mime = FILES[file_id]
    if alt != "media":
        return Response(
            f'{{"kind":"drive#file","id":"{file_id}","name":"{name}","mimeType":"{mime}"}}',
            media_type="application/json",
        )
    data = _content(file_id)
    if "range" in request.headers:
        start, _, end = request.headers["range"].removeprefix("bytes=").partition("-")
        last = min(int(end or len(data) - 1), len(data) - 1)
        return Response(
            data[int(start) : last + 1],
            status_code=206,
            media_type=mime,
            headers={"Content-Range": f"bytes {start}-{last}/{len(data)}"},
        )
    return Response(data, media_type=mime)
