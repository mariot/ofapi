"""witha.name: DDoSIA target configurations, read by the OpenCTI withaname connector."""

import time

from fastapi import APIRouter

from app.fake import fake

HOSTS = ["witha.name"]
router = APIRouter(prefix="/withaname", tags=["Withaname"])

PAGE_SIZE = 2
SNAPSHOTS = 3
ATTACKS = ["http", "http2", "nginx_loris", "tcp", "syn", "dns_flood"]


@router.get("/api/configs")
async def configs(page: int = 1) -> dict:
    """Snapshots, most recent first, PAGE_SIZE per page."""
    now = time.time()
    items = [
        {"id": fake.sha1()[:16], "ts": round(now - 3600 * (n + 1), 3)}
        for n in range(SNAPSHOTS)
    ]
    start = (page - 1) * PAGE_SIZE
    return {"items": items[start : start + PAGE_SIZE], "total": SNAPSHOTS}


@router.get("/api/config/{cfg_id}")
async def config(cfg_id: str) -> dict:
    """The targets of one snapshot: several per host, a few hosts."""
    targets = []
    for _ in range(4):
        host = fake.domain_name()
        ip = fake.ipv4_public()
        for _ in range(2):
            targets.append(
                {
                    "host": host,
                    "ip": ip if fake.boolean() else fake.ipv4_public(),
                    "type": fake.random_element(ATTACKS),
                    "method": "GET",
                    "port": 443,
                    "use_ssl": True,
                    "path": "/",
                }
            )
    targets.append(
        {"host": f"HTTPS://{fake.domain_name()}:8443", "ip": "", "type": "tcp"}
    )
    return {"id": cfg_id, "targets": targets}
