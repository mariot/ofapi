"""Com Laude: login and domain search, read by the OpenCTI comlaude connector."""

import base64
import json
import time
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter

from app.fake import fake

HOSTS = ["api.comlaude.com"]
router = APIRouter(prefix="/comlaude", tags=["Com Laude"])


def _b64(data: dict) -> str:
    raw = json.dumps(data).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _jwt(lifetime: timedelta) -> str:
    """An unsigned-looking JWT: the connector only decodes its ``exp`` claim."""
    claims = {"sub": fake.uuid4(), "exp": int(time.time() + lifetime.total_seconds())}
    return f"{_b64({'alg': 'HS256', 'typ': 'JWT'})}.{_b64(claims)}.{fake.sha256()[:43]}"


def _domain(group_id: str, created: datetime) -> dict:
    now = datetime.now(UTC)
    stamp = "%Y-%m-%dT%H:%M:%SZ"
    return {
        "id": fake.uuid4(),
        "name": fake.domain_name(),
        "created_at": created.strftime(stamp),
        "updated_at": (created + timedelta(hours=fake.random_int(1, 48))).strftime(
            stamp
        ),
        "expires_at": (now + timedelta(days=fake.random_int(30, 700))).strftime(stamp),
        "status": "active",
        "group_id": group_id,
    }


@router.post("/api_login")
async def api_login() -> dict:
    """A bearer token valid for two days."""
    return {
        "data": {
            "access_token": _jwt(timedelta(days=2)),
            "refresh_token": fake.sha256(),
            "token_type": "Bearer",
            "expires_in": 172800,
        }
    }


@router.post("/groups/{group_id}/domains/search")
async def search_domains(group_id: str, page: int = 1, limit: int = 500) -> dict:
    """Two pages of domains: the connector follows ``pagination.next``."""
    last = 2
    created = datetime.now(UTC) - timedelta(days=3)
    domains = [_domain(group_id, created + timedelta(hours=i)) for i in range(5)]
    return {
        "data": domains,
        "pagination": {
            "page": page,
            "limit": limit,
            "total": 5 * last,
            "next": None if page >= last else page + 1,
            "previous": None if page <= 1 else page - 1,
        },
    }
