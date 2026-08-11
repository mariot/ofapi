"""Factories for the isMalicious API (``api.ismalicious.com``).

The OpenCTI ``ismalicious`` internal-enrichment connector calls a single
endpoint, ``GET /check``, and reads ``malicious``, ``confidenceScore``,
``reputation``, ``categories``, ``sources``, ``geo`` and ``metadata`` from the
answer.
"""

from dataclasses import dataclass, field

import factory
from factory import fuzzy

THREAT_CATEGORIES = [
    "malware",
    "phishing",
    "botnet",
    "spam",
    "scam",
    "ransomware",
    "command-and-control",
    "cryptomining",
    "exploit-kit",
]

THREAT_LEVELS = ["low", "medium", "high", "critical"]


@dataclass
class Reputation:
    malicious: int
    suspicious: int
    harmless: int
    undetected: int


@dataclass
class Source:
    name: str
    category: str
    url: str


@dataclass
class Geo:
    country: str
    countryCode: str  # noqa: N815 - mirrors the vendor's camelCase payload
    city: str
    asn: str


@dataclass
class Metadata:
    threatLevel: str  # noqa: N815 - mirrors the vendor's camelCase payload
    firstSeen: str  # noqa: N815 - mirrors the vendor's camelCase payload
    lastSeen: str  # noqa: N815 - mirrors the vendor's camelCase payload


@dataclass
class CheckResult:
    query: str
    malicious: bool
    confidenceScore: int  # noqa: N815 - mirrors the vendor's camelCase payload
    categories: list[str]
    reputation: Reputation
    sources: list[Source]
    geo: Geo
    metadata: Metadata
    tags: list[str] = field(default_factory=list)


class ReputationFactory(factory.Factory):
    class Meta:
        model = Reputation

    malicious = factory.Faker("random_int", min=1, max=20)
    suspicious = factory.Faker("random_int", min=0, max=10)
    harmless = factory.Faker("random_int", min=0, max=30)
    undetected = factory.Faker("random_int", min=0, max=30)


class SourceFactory(factory.Factory):
    class Meta:
        model = Source

    name = factory.Faker("company")
    category = fuzzy.FuzzyChoice(THREAT_CATEGORIES)
    url = factory.Faker("url")


class GeoFactory(factory.Factory):
    class Meta:
        model = Geo

    country = factory.Faker("country")
    countryCode = factory.Faker("country_code")
    city = factory.Faker("city")
    asn = factory.Faker("bothify", text="AS#####")


class MetadataFactory(factory.Factory):
    class Meta:
        model = Metadata

    threatLevel = fuzzy.FuzzyChoice(THREAT_LEVELS)
    firstSeen = factory.Faker("iso8601")
    lastSeen = factory.Faker("iso8601")


class CheckResultFactory(factory.Factory):
    class Meta:
        model = CheckResult

    query = factory.Faker("ipv4")
    malicious = True
    confidenceScore = factory.Faker("random_int", min=50, max=100)
    categories = factory.List([fuzzy.FuzzyChoice(THREAT_CATEGORIES) for _ in range(2)])
    reputation = factory.SubFactory(ReputationFactory)
    sources = factory.List([factory.SubFactory(SourceFactory) for _ in range(3)])
    geo = factory.SubFactory(GeoFactory)
    metadata = factory.SubFactory(MetadataFactory)
    tags = factory.List([fuzzy.FuzzyChoice(THREAT_CATEGORIES) for _ in range(2)])
