from factory import Factory, Faker, LazyAttribute
from pydantic import BaseModel


class AlertEvent(BaseModel):
    actor_process_image_name: str | None = None


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
    # Populated by the get_alerts_multi_events endpoint so the collector can
    # find the implant directly without needing get_original_alerts enrichment.
    events: list[AlertEvent] | None = None


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


# --- get_original_alerts (used by AlertFetcher to enrich alerts that have no
# direct implant in their events, by parsing the raw messageData.processes) ---


class OriginalAlertItem(BaseModel):
    internal_id: int
    original_alert_json: str = "{}"


class GetOriginalAlertsResponseItem(BaseModel):
    alerts: list[OriginalAlertItem] = []


class GetOriginalAlertsResponse(BaseModel):
    reply: GetOriginalAlertsResponseItem


# --- get_incident_extra_data (defined on the client but not currently called
# by AlertFetcher; kept for completeness/future use) ---


class IncidentItem(BaseModel):
    incident_id: int


class FileArtifact(BaseModel):
    file_name: str


class FileArtifacts(BaseModel):
    total_count: int = 0
    data: list[FileArtifact] = []


class Alerts(BaseModel):
    total_count: int = 0
    data: list[Alert] = []


class Incident(BaseModel):
    incident: IncidentItem
    alerts: Alerts
    file_artifacts: FileArtifacts


class GetIncidentExtraDataResponse(BaseModel):
    reply: Incident
