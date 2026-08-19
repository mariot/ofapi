from factory import Factory, Faker, LazyAttribute
from pydantic import BaseModel, ConfigDict, Field


class Alert(BaseModel):
    """Represents an alert inside an XSOAR incident (CustomFields.xdralerts).

    Mirrors ``src/models/incident.py::Alert`` from the palo-alto-cortex-xsoar
    collector."""

    alert_id: str
    case_id: int | None = None
    action_pretty: str | None = None
    actor_process_command_line: str | None = None
    actor_process_image_name: str | None = None
    actor_process_image_path: str | None = None
    detection_timestamp: int
    external_id: str | None = None
    severity: str | None = None
    matching_status: str | None = None
    category: str | None = None
    description: str | None = None
    action: str | None = None


class CustomFields(BaseModel):
    model_config = ConfigDict(extra="allow")

    xdralerts: list[Alert] = Field(default_factory=list)


class Incident(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    id: str
    name: str | None = None
    type: str | None = None
    status: int | None = None
    severity: int | None = None
    custom_fields: CustomFields | None = Field(None, alias="CustomFields")


class XSOARSearchIncidentsResponse(BaseModel):
    total: int = 0
    data: list[Incident] = []


class AlertFactory(Factory):
    class Meta:
        model = Alert

    alert_id = Faker("uuid4")
    case_id = Faker("random_int", min=1, max=1000)
    action_pretty = "Detected (Reported)"
    actor_process_command_line = Faker("sentence")
    actor_process_image_name = Faker("file_name", extension="exe")
    actor_process_image_path = Faker("file_path")
    _detection_timestamp = Faker("unix_time")
    detection_timestamp = LazyAttribute(lambda obj: int(obj._detection_timestamp))
    external_id = Faker("uuid4")
    severity = Faker("random_element", elements=["low", "medium", "high"])
    matching_status = "UNMATCHABLE"
    category = "Malware"
    description = Faker("sentence")
    action = "Reported"


class IncidentFactory(Factory):
    class Meta:
        model = Incident

    id = Faker("uuid4")
    name = Faker("sentence")
    type = "Malware"
    status = 1
    severity = 2
