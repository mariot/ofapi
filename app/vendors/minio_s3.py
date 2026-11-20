"""MinIO as a client with no proxy support sees it: path-style S3 at the root of ofapi.

The minio-py client opens its own connections (no proxy variables), so the OpenCTI
stream-exporter and stream-importer connectors are pointed at ofapi itself, with
buckets named ``sfminio-<anything>``. Their requests are served by the S3 emulation
of ``aws.py`` (moto), which keeps the objects until ofapi restarts.
"""

from fastapi import APIRouter, Request, Response
from starlette.concurrency import run_in_threadpool

from app.vendors import aws

HOSTS = ["minio.staticfire.test"]
router = APIRouter(tags=["MinIO"])

METHODS = ["GET", "HEAD", "PUT", "POST", "DELETE"]


async def _s3(request: Request) -> Response:
    headers = {
        k: v
        for k, v in request.headers.items()
        if k.lower() not in {"host", "x-original-host"}
    }
    headers["Host"] = "s3.us-east-1.amazonaws.com"
    if "authorization" not in {k.lower() for k in headers}:
        headers["Authorization"] = aws._unsigned_scope(headers["Host"])
    status, response_headers, content = await run_in_threadpool(
        aws._call,
        request.method,
        request.url.path,
        request.url.query,
        headers,
        await request.body(),
    )
    return Response(
        content=content,
        status_code=int(status.split()[0]),
        headers={
            k: v for k, v in response_headers.items() if k.lower() not in aws.HOP_BY_HOP
        },
    )


router.add_api_route("/sfminio-{bucket}", _s3, methods=METHODS, include_in_schema=False)
router.add_api_route(
    "/sfminio-{bucket}/{key:path}", _s3, methods=METHODS, include_in_schema=False
)
