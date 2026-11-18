from datetime import UTC, datetime

from factory import Factory, Faker, LazyAttribute, LazyFunction
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


class ProcessDetails(BaseModel):
    filename: str


class DeviceDetails(BaseModel):
    hostname: str


class Alert(BaseModel):
    """The subset of a Falcon alert (``type:'ldt'``) the OpenAEV collector reads."""

    id: str
    composite_id: str
    severity: int
    status: str
    display_name: str
    filename: str
    parent_details: ProcessDetails
    grandparent_details: ProcessDetails
    device: DeviceDetails
    # Bitmask of the actions Falcon took: 0 is detection only, 2048 a blocked process
    pattern_disposition: int
    pattern_disposition_description: str = ""
    created_timestamp: str
    updated_timestamp: str


class EntitiesAlertsRequest(BaseModel):
    composite_ids: list[str] = []


class QueryAlertsResponse(BaseModel):
    errors: list = []
    meta: dict = {
        "query_time": 0.01,
        "pagination": {"limit": 100, "offset": 0, "total": 0},
    }
    resources: list[str] = []


class EntitiesAlertsResponse(BaseModel):
    errors: list = []
    meta: dict = {"query_time": 0.01}
    resources: list[Alert] = []


class AlertFactory(Factory):
    class Meta:
        model = Alert

    composite_id = Faker("uuid4")
    id = LazyAttribute(lambda alert: alert.composite_id.rsplit(":", 1)[-1])
    severity = 70
    status = "new"
    display_name = "SuspiciousActivity"
    filename = Faker("file_name", extension="exe")
    parent_details = LazyFunction(lambda: ProcessDetails(filename="powershell.exe"))
    grandparent_details = LazyFunction(lambda: ProcessDetails(filename="explorer.exe"))
    device = LazyFunction(lambda: DeviceDetails(hostname="win-endpoint"))
    pattern_disposition = 0
    pattern_disposition_description = "Detection, standard detection."
    created_timestamp = LazyFunction(
        lambda: datetime.now(UTC).isoformat().replace("+00:00", "Z")
    )
    updated_timestamp = LazyAttribute(lambda alert: alert.created_timestamp)
