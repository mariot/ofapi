from factory import Factory, Faker, LazyAttribute
from pydantic import BaseModel


class Alert(BaseModel):
    external_id: str
    severity: str
    matching_status: str
    case_id: int
    alert_id: int
    actor_process_command_line: str = ""
    category: str
    description: str
    action: str
    action_pretty: str
    detection_timestamp: int


class GetAlertsResponseItem(BaseModel):
    total_count: int | None
    result_count: int | None
    alerts: list[Alert]


class GetAlertsResponse(BaseModel):
    reply: GetAlertsResponseItem


class AlertFactory(Factory):
    class Meta:
        model = Alert

    external_id = Faker("uuid4")
    actor_process_command_line = Faker("sentence")
    severity = Faker("random_element", elements=["low", "medium", "high"])
    matching_status = "UNMATCHABLE"
    case_id = Faker("random_int", min=1, max=1000)
    alert_id = Faker("random_int", min=1, max=10000)
    category = "Malware"
    description = Faker("sentence")
    action = "Reported"
    action_pretty = "Detected (Reported)"
    _detection_timestamp = Faker("unix_time")
    detection_timestamp = LazyAttribute(lambda obj: int(obj._detection_timestamp))
