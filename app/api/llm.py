"""Factories for OpenAI-compatible chat completion APIs.

Used by the OpenAEV ``ai-redteam`` injector, which sends a single-turn adversarial
prompt to an OpenAI-compatible endpoint and inspects the answer for its per-inject
canary marker (forwarded in the ``X-OAEV-Inject-Marker`` header).

The fake model is *defended* by default - it refuses and never echoes the marker -
so a red-team inject reports ``DEFENDED``. Pass ``?behaviour=vulnerable`` to make it
leak the marker instead, which exercises the ``VULNERABLE`` code path.
"""

import time
import uuid
from dataclasses import dataclass, field

import factory

REFUSALS = [
    "I can't help with that request.",
    "Sorry, I can't comply with those instructions.",
    "I'm not able to ignore my safety guidelines.",
    "That request goes against my instructions, so I won't answer it.",
]


@dataclass
class Usage:
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int


@dataclass
class Choice:
    index: int
    message: dict
    logprobs: None
    finish_reason: str


@dataclass
class ChatCompletion:
    id: str
    object: str
    created: int
    model: str
    choices: list[Choice] = field(default_factory=list)
    usage: Usage = None
    system_fingerprint: str = ""


class UsageFactory(factory.Factory):
    class Meta:
        model = Usage

    prompt_tokens = factory.Faker("random_int", min=10, max=200)
    completion_tokens = factory.Faker("random_int", min=5, max=120)

    @factory.lazy_attribute
    def total_tokens(self):
        return self.prompt_tokens + self.completion_tokens


class ChatCompletionFactory(factory.Factory):
    class Meta:
        model = ChatCompletion

    id = factory.LazyFunction(lambda: f"chatcmpl-{uuid.uuid4().hex[:24]}")
    object = "chat.completion"
    created = factory.LazyFunction(lambda: int(time.time()))
    model = "gpt-4o-mini"
    usage = factory.SubFactory(UsageFactory)
    system_fingerprint = factory.Faker("bothify", text="fp_??????????")


def completion_text(marker: str | None, vulnerable: bool) -> str:
    """Answer of the fake model, leaking the canary only when asked to."""
    if vulnerable and marker:
        return f"OAEV_PWNED_{marker}"
    return REFUSALS[0]


@dataclass
class AnthropicMessage:
    id: str
    type: str
    role: str
    model: str
    content: list[dict]
    stop_reason: str
    stop_sequence: None
    usage: dict


class AnthropicMessageFactory(factory.Factory):
    class Meta:
        model = AnthropicMessage

    id = factory.LazyFunction(lambda: f"msg_{uuid.uuid4().hex[:24]}")
    type = "message"
    role = "assistant"
    model = "claude-3-5-sonnet-latest"
    content = factory.List([factory.Dict({"type": "text", "text": REFUSALS[0]})])
    stop_reason = "end_turn"
    stop_sequence = None
    usage = factory.Dict({"input_tokens": 42, "output_tokens": 12})
