"""FortiSandbox: the JSON-RPC API (fortisandbox enrichment connector)."""

from fastapi import APIRouter, Request

from app.fake import fake

HOSTS = ["fortisandbox.staticfire.test"]
router = APIRouter(prefix="/fortisandbox", tags=["FortiSandbox"])

SESSION = "staticfire-fortisandbox-session"


def _answer(url: str, data: dict | list | None = None, code: int = 0) -> dict:
    message = "OK" if code == 0 else "Invalid params"
    result = {"url": url, "status": {"code": code, "message": message}}
    if data is not None:
        result["data"] = data
    return {"id": 1, "result": result, "session": SESSION}


def _rating(checksum: str, ctype: str = "sha256") -> dict:
    hashes = {"sha256": fake.sha256(), "sha1": fake.sha1(), "md5": fake.md5()}
    hashes[ctype] = checksum
    return {
        "rating": fake.random_element(["Malicious", "High Risk", "Medium Risk"]),
        "malware_name": fake.malware_family(),
        **hashes,
        "start_ts": fake.unix_time(),
        "finish_ts": fake.unix_time(),
        "detail_url": f"https://fortisandbox.staticfire.test/job/{checksum}",
        "vid": fake.random_int(1000, 9999),
    }


@router.post("/jsonrpc")
async def jsonrpc(request: Request) -> dict:
    """Dispatch on the url of the first parameter, as the real appliance does."""
    body = await request.json()
    params = (body.get("params") or [{}])[0]
    url = params.get("url", "")
    if url == "/sys/login/user":
        return _answer(url)
    if url == "/sys/logout":
        return _answer(url)
    if url == "/scan/result/filerating":
        checksum = params.get("checksum", "")
        if checksum.startswith("00"):
            return _answer(url, {"rating": "Unknown"})
        return _answer(url, _rating(checksum, params.get("ctype", "sha256")))
    if url == "/alert/ondemand/submit-file":
        return _answer(url, {"sid": str(fake.random_int(100000, 999999))})
    if url == "/scan/result/get-jobs-of-submission":
        return _answer(url, [{"jid": str(fake.random_int(100000, 999999))}])
    if url == "/scan/result/job":
        return _answer(url, _rating(fake.sha256()))
    return _answer(url, code=-6)
