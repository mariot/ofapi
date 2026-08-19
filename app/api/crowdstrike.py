from factory import Factory, Faker
from pydantic import BaseModel


class TokenResponse(BaseModel):
    access_token: str
    expires_in: int
    token_type: str


class TokenResponseFactory(Factory):
    class Meta:
        model = TokenResponse

    access_token = Faker("sha256")
    expires_in = 1799
    token_type = "bearer"


class Alert(BaseModel):
    composite_id: str
    severity: int
    status: str
    pattern_disposition_description: str = ""
    parent_details: dict = {}


class QueryAlertsResponse(BaseModel):
    errors: list = []
    meta: dict = {"query_time": 0.01, "pagination": {"limit": 100, "offset": 0, "total": 0}}
    resources: list[str] = []


class EntitiesAlertsResponse(BaseModel):
    errors: list = []
    meta: dict = {"query_time": 0.01}
    resources: list[Alert] = []


class AlertFactory(Factory):
    class Meta:
        model = Alert

    composite_id = Faker("uuid4")
    severity = 70
    status = "new"
