"""ClickHouse: the HTTP interface (DDL and ``INSERT ... FORMAT JSONEachRow``), read by
the OpenCTI clickhouse stream connector. The server is self-hosted, so it lives on a
test host."""

from fastapi import APIRouter, HTTPException, Query, Request, Response

HOSTS = ["clickhouse.staticfire.test"]
router = APIRouter(prefix="/clickhouse", tags=["ClickHouse"])

PASSWORD = "staticfire-fake-password"


@router.post("/")
async def query(request: Request, query: str = Query("")) -> Response:
    """Runs the statement of ``query`` (the body carries the rows of an INSERT)."""
    if request.headers.get("authorization", "").lower().startswith("basic ") is False:
        raise HTTPException(401, "Code: 516. Authentication failed")
    statement = query.strip().upper()
    if not statement.startswith(("CREATE ", "INSERT ")):
        raise HTTPException(400, f"Code: 62. Syntax error: {query}")
    if statement.startswith("INSERT ") and not await request.body():
        raise HTTPException(400, "Code: 117. Empty INSERT")
    return Response(status_code=200, media_type="text/tab-separated-values")
