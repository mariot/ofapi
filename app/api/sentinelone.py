from factory import Factory, Faker, SubFactory
from pydantic import BaseModel


class ThreatInfo(BaseModel):
    threatId: str  # noqa: N815 - field name mirrors the vendor's camelCase API
    sha1: str = ""
    detectionType: str = "static"  # noqa: N815


class AgentRealtimeInfo(BaseModel):
    agentComputerName: str = ""  # noqa: N815


class MitigationStatusItem(BaseModel):
    status: str = "success"


class Threat(BaseModel):
    """Mirrors the raw shape consumed by
    ``SentinelOneThreatsResponse.from_raw_response`` (threatInfo/
    agentRealtimeInfo/mitigationStatus), not the flattened ``SentinelOneThreat``
    model built from it."""

    threatInfo: ThreatInfo  # noqa: N815
    agentRealtimeInfo: AgentRealtimeInfo = AgentRealtimeInfo()  # noqa: N815
    mitigationStatus: list[MitigationStatusItem] = []  # noqa: N815


class ThreatsResponse(BaseModel):
    data: list[Threat] = []


class ThreatEventsResponse(BaseModel):
    data: list[dict] = []


class DVInitQueryData(BaseModel):
    queryId: str  # noqa: N815


class DVInitQueryResponse(BaseModel):
    data: DVInitQueryData


class DVQueryStatusData(BaseModel):
    progressStatus: int = 100  # noqa: N815
    responseState: str = "FINISHED"  # noqa: N815


class DVQueryStatusResponse(BaseModel):
    data: DVQueryStatusData


class DVEventsResponse(BaseModel):
    data: list[dict] = []


class ThreatInfoFactory(Factory):
    class Meta:
        model = ThreatInfo

    threatId = Faker("uuid4")
    sha1 = Faker("sha1")
    detectionType = "static"


class ThreatFactory(Factory):
    class Meta:
        model = Threat

    threatInfo = SubFactory(ThreatInfoFactory)
    agentRealtimeInfo = AgentRealtimeInfo(agentComputerName="fake-host")
    mitigationStatus = [MitigationStatusItem(status="success")]
