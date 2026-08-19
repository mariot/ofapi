from pydantic import BaseModel


class Agent(BaseModel):
    slug: str
    enabled: bool = True
    disable_chat: bool = False


class AgentsResponse(BaseModel):
    items: list[Agent] = []


class AuditLogsResponse(BaseModel):
    items: list[dict] = []
    total: int = 0
