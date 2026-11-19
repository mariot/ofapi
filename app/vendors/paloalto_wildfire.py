"""Palo Alto Networks WildFire public API: the verdict and report of a hash (XML), read
by the OpenCTI paloalto-wildfire connector. The sample is always known and malicious."""

import re

from fastapi import APIRouter, Form, Response

from app.fake import fake

HOSTS = ["wildfire.paloaltonetworks.com"]
router = APIRouter(prefix="/paloalto-wildfire", tags=["Palo Alto WildFire"])


def _xml(body: str) -> Response:
    return Response(content=body, media_type="text/xml")


@router.post("/publicapi/get/verdict")
async def verdict(hash: str = Form("")) -> Response:  # noqa: A002
    """Verdict 1 (malware) for any hash."""
    return _xml(
        '<?xml version="1.0" encoding="UTF-8"?><wildfire><get-verdict-info>'
        f"<sha256>{hash}</sha256><verdict>1</verdict><md5>{fake.md5()}</md5>"
        "</get-verdict-info></wildfire>"
    )


@router.post("/publicapi/get/report")
async def report(hash: str = Form("")) -> Response:  # noqa: A002
    """The file information of the report, on the hash asked."""
    sha256 = hash if re.fullmatch(r"[0-9a-f]{64}", hash) else fake.sha256()
    return _xml(
        '<?xml version="1.0" encoding="UTF-8"?><wildfire><version>2.0</version>'
        "<file_info><file_signer>None</file_signer><malware>yes</malware>"
        f"<sha1>{fake.sha1()}</sha1><filetype>PE</filetype><sha256>{sha256}</sha256>"
        f"<md5>{fake.md5()}</md5><size>{fake.random_int(20_000, 900_000)}</size>"
        "</file_info></wildfire>"
    )
