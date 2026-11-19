"""Receiver for the staticfire test of the backup-files stream connector.

The connector writes to a local directory and calls no API: the test posts the backup
files it found there, so that the journal shows what the connector saved.
"""

from fastapi import APIRouter, Request

HOSTS = ["backup-files.staticfire.test"]
router = APIRouter(prefix="/backup-files", tags=["Backup files"])


@router.post("/files")
async def files(request: Request) -> dict:
    """A backup file the connector wrote (its name and content)."""
    body = await request.json()
    return {"stored": body.get("name")}
