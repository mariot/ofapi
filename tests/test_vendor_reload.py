from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import vendors
from app.main import app

MODULE = Path(vendors.__path__[0]) / "zz_reload_probe.py"


@pytest.fixture
def probe():
    yield MODULE
    MODULE.unlink(missing_ok=True)
    vendors.reload_into(app)


def _write(answer: str) -> None:
    MODULE.write_text(
        "from fastapi import APIRouter\n"
        'HOSTS = ["api.probe.example", "*.probe.example"]\n'
        'router = APIRouter(prefix="/probe")\n'
        '@router.get("/ping")\n'
        f"def ping(): return {{'answer': '{answer}'}}\n"
    )


@pytest.mark.usefixtures("probe")
def test_new_and_changed_vendor_modules_load_without_a_restart():
    client = TestClient(app)
    assert client.get("/probe/ping").status_code == 404
    _write("first")
    assert "zz_reload_probe" in client.post("/_control/reload").json()["reloaded"]
    assert client.get("/probe/ping").json() == {"answer": "first"}
    assert client.get("/_control/hosts").json()["*.probe.example"] == "/probe"

    import os
    import time

    _write("second")
    later = time.time() + 5
    os.utime(MODULE, (later, later))
    client.post("/_control/reload")
    assert client.get("/probe/ping").json() == {"answer": "second"}
    paths = [getattr(r, "path", "") for r in app.router.routes]
    assert paths.count("/probe/ping") == 1


def test_reset_can_keep_other_vendors():
    client = TestClient(app)
    client.post("/_control/reset")
    for path in ("/a/x", "/b/x"):
        rule = {"path": path, "responses": [{"status": 418}]}
        client.post("/_control/rules", json=rule)
    client.get("/a/x")
    client.get("/b/x")
    client.post("/_control/reset", params={"prefix": "/a"})
    assert [r["path"] for r in client.get("/_control/rules").json()] == ["/b/x"]
    assert {e["path"] for e in client.get("/_control/journal").json()} == {"/b/x"}
