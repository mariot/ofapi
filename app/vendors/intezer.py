"""Intezer Analyze: the API v2 sandbox (file analysis), read by the intezer-sandbox
enrichment connector."""

from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse

from app.fake import fake

HOSTS = ["analyze.intezer.com"]
router = APIRouter(prefix="/intezer", tags=["Intezer"])

# analysis id -> polls so far: the first poll finds the analysis still running
POLLS: dict[str, int] = {}
FAMILIES = ["Emotet", "TrickBot", "AgentTesla", "Cobalt Strike", "Ryuk", "njRAT"]


@router.post("/api/v2-0/get-access-token")
async def get_access_token(request: Request) -> Response:
    """Exchanges the API key for a bearer token."""
    body = await request.json()
    if not body.get("api_key"):
        return JSONResponse({"message": "api_key is required"}, status_code=400)
    return JSONResponse({"result": fake.sha256()})


@router.post("/api/v2-0/analyze", status_code=201)
async def analyze(request: Request) -> dict:
    """Accepts a file and answers with where its analysis will be."""
    await request.body()
    analysis_id = fake.uuid4()
    POLLS[analysis_id] = 0
    return {
        "result": f"/analyses/{analysis_id}",
        "result_url": f"/analyses/{analysis_id}",
    }


@router.get("/api/v2-0/analyses/{analysis_id}")
async def analysis(analysis_id: str, response: Response) -> dict:
    """In progress (202) on the first poll, then the verdict."""
    polls = POLLS.get(analysis_id, 0)
    POLLS[analysis_id] = polls + 1
    result_url = f"/analyses/{analysis_id}"
    if polls == 0:
        response.status_code = 202
        return {"result_url": result_url, "status": "in_progress"}
    return {
        "result": {
            "analysis_id": analysis_id,
            "analysis_time": fake.date_time_this_month().strftime(
                "%a, %d %b %Y %H:%M:%S GMT"
            ),
            "analysis_url": f"https://analyze.intezer.com/analyses/{analysis_id}",
            "family_name": fake.random_element(FAMILIES),
            "is_private": True,
            "sha256": fake.sha256(),
            "sub_verdict": "malicious",
            "verdict": "malicious",
        },
        "result_url": result_url,
        "status": "succeeded",
    }
