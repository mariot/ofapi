"""Intelfinder: the alerts API (getAlerts), read by the intelfinder import connector."""

from fastapi import APIRouter, Request

from app.fake import fake

HOSTS = ["dash.intelfinder.io"]
router = APIRouter(prefix="/intelfinder", tags=["Intelfinder"])

API_KEY_LENGTH = 24


def _id() -> str:
    return fake.hexify("^" * 24)


def _elements() -> list[dict]:
    domain = fake.domain_name()
    return [
        {"label": "Domain", "value": domain},
        {
            "label": "Similar to Domain",
            "value": "\n".join(fake.domain_name() for _ in range(2)),
        },
        {"label": "Name Server 1", "value": f"ns1.{domain}"},
        {"label": "Mail Server 1", "value": f"mail.{domain}"},
        {"label": "IP Address", "value": fake.ipv4_public()},
        {"label": "IP Address (v6)", "value": fake.ipv6()},
        {"label": "URL", "value": f"https://{domain}/{fake.slug()}"},
        {"label": "Registrar", "value": fake.company()},
        {
            "label": "Raw WHOIS",
            "value": f"Domain: {domain}\nRegistrar: {fake.company()}",
        },
    ]


def _leak_elements() -> list[dict]:
    return [
        {
            "label": "Record 1",
            "value": "\n".join(
                [
                    f"URL: https://{fake.domain_name()}/login",
                    f"Email: {fake.email()}",
                    f"Username: {fake.user_name()}",
                    f"Password: {fake.password()}",
                ]
            ),
        },
        {
            "label": "Record 2",
            "value": (
                f"Emails: {fake.email()}, {fake.email()}\nUser: {fake.user_name()}"
            ),
        },
        {"label": "IP Address", "value": fake.ipv4_public()},
    ]


def _alert(title: str, elements: list[dict]) -> dict:
    added = fake.date_time_between(start_date="-5d", end_date="-1d")
    updated = fake.date_time_between(start_date=added, end_date="now")
    steps = [fake.sentence() for _ in range(2)]
    return {
        "_id": _id(),
        "update_id": _id(),
        "title": title,
        "priority": fake.random_int(1, 5),
        "added_on": added.strftime("%Y-%m-%d %H:%M:%S"),
        "last_update": updated.strftime("%Y-%m-%d %H:%M:%S"),
        "description": f"<p>{fake.paragraph()}</p>",
        "details": f"<p>{fake.sentence()}</p><h3>Elements</h3>%elements%",
        "recommendation": f"<ul><li>{steps[0]}</li><li>{steps[1]}</li></ul>",
        "elements": elements,
    }


@router.post("/api.php")
async def api(request: Request) -> dict:
    """getAlerts: a few new alerts (fewer than a page of 20, so the last one)."""
    form = await request.form()
    key = str(form.get("key") or "")
    if len(key) != API_KEY_LENGTH:
        return {"code": 1, "error": "API key is either invalid or not provided"}
    if form.get("action") != "getAlerts":
        return {
            "code": 3,
            "error": "Parameter 'action' is either invalid or not provided",
        }
    alerts = [
        _alert(f"Typosquatting domain targeting {fake.company()}", _elements()),
        _alert(f"Phishing page impersonating {fake.company()}", _elements()),
        _alert(f"Leaked credentials of {fake.company()} employees", _leak_elements()),
    ]
    return {"code": 0, "alerts": alerts}
