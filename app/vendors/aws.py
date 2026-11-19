"""Amazon Web Services, emulated by moto: S3, STS, EC2, SQS, Cognito... all moto covers.

The proxy sends ``https://<anything>.amazonaws.com/...`` here with the real host in
``X-Original-Host``; moto picks the service (and the S3 bucket of a virtual-hosted
URL) from that host, so SDKs work unchanged. Requests are not signature-checked.
State lives in this process until ofapi restarts: a test seeds what it needs through
the same API (``PUT /aws/<bucket>/<key>`` with ``X-Original-Host: s3.amazonaws.com``,
or any SDK call).

Hosts claimed exactly by another module (a vendor's own Cognito or bucket) stay with it.
"""

from fastapi import APIRouter, Request, Response
from moto.server import DomainDispatcherApplication, create_backend_app
from starlette.concurrency import run_in_threadpool
from werkzeug.test import EnvironBuilder, run_wsgi_app

HOSTS = ["*.amazonaws.com", "amazonaws.com"]
router = APIRouter(prefix="/aws", tags=["AWS"])

_moto = DomainDispatcherApplication(create_backend_app)
HOP_BY_HOP = {"connection", "keep-alive", "transfer-encoding", "content-length"}


def _unsigned_scope(host: str) -> str:
    """moto picks the service from a request's SigV4 scope: one for an unsigned request,
    from its host (``<bucket>.s3.<region>.amazonaws.com``, ``sts.amazonaws.com``...)."""
    labels = host.split(":")[0].removesuffix(".amazonaws.com").split(".")
    if "s3" in labels or any(label.startswith("s3-") for label in labels):
        service = "s3"
    else:
        service = labels[0]
    region = next((x for x in labels if x.count("-") >= 2), "us-east-1")
    return (
        f"AWS4-HMAC-SHA256 Credential=AKIDSTATICFIRE/20260101/{region}/{service}/"
        "aws4_request, SignedHeaders=host, Signature=0"
    )


def _call(method: str, path: str, query: str, headers: dict, body: bytes):
    environ = EnvironBuilder(
        path=path,
        method=method,
        query_string=query,
        headers=headers,
        data=body,
        base_url=f"https://{headers['Host']}",
    ).get_environ()
    app_iter, status, response_headers = run_wsgi_app(_moto, environ)
    try:
        content = b"".join(app_iter)
    finally:
        getattr(app_iter, "close", lambda: None)()
    return status, response_headers, content


@router.api_route(
    "/{path:path}", methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"]
)
async def emulate(path: str, request: Request) -> Response:
    headers = {
        k: v
        for k, v in request.headers.items()
        if k.lower() not in {"host", "x-original-host"}
    }
    headers["Host"] = request.headers.get("x-original-host", "s3.amazonaws.com")
    if "authorization" not in {k.lower() for k in headers}:
        headers["Authorization"] = _unsigned_scope(headers["Host"])
    status, response_headers, content = await run_in_threadpool(
        _call,
        request.method,
        "/" + path,
        request.url.query,
        headers,
        await request.body(),
    )
    return Response(
        content=content,
        status_code=int(status.split()[0]),
        headers={
            k: v for k, v in response_headers.items() if k.lower() not in HOP_BY_HOP
        },
    )
