"""Factories for the Shodan REST API (``api.shodan.io``).

Covers the two endpoints the OpenAEV Shodan injector calls: ``/shodan/host/search``
and ``/api-info``.
"""

from dataclasses import dataclass, field

import factory
from factory import fuzzy

OPERATING_SYSTEMS = [
    "Linux 3.x",
    "Linux 5.x",
    "Windows Server 2019",
    "Windows 10",
    "FreeBSD",
]

PRODUCTS = ["nginx", "Apache httpd", "OpenSSH", "Microsoft IIS httpd", "PostgreSQL"]


@dataclass
class MatchLocation:
    city: str
    country_name: str
    country_code: str
    longitude: float
    latitude: float


@dataclass
class Match:
    ip_str: str
    hostnames: list[str]
    domains: list[str]
    os: str
    port: int
    transport: str
    org: str
    isp: str
    asn: str
    product: str
    version: str
    timestamp: str
    location: MatchLocation
    data: str
    vulns: dict = field(default_factory=dict)


@dataclass
class UsageLimits:
    scan_credits: int
    query_credits: int
    monitored_ips: int


@dataclass
class ApiInfo:
    scan_credits: int
    query_credits: int
    plan: str
    https: bool
    unlocked: bool
    unlocked_left: int
    telnet: bool
    monitored_ips: int
    usage_limits: UsageLimits


class MatchLocationFactory(factory.Factory):
    class Meta:
        model = MatchLocation

    city = factory.Faker("city")
    country_name = factory.Faker("country")
    country_code = factory.Faker("country_code")
    longitude = factory.Faker("longitude")
    latitude = factory.Faker("latitude")


class MatchFactory(factory.Factory):
    class Meta:
        model = Match

    ip_str = factory.Faker("ipv4_public")
    hostnames = factory.List([factory.Faker("domain_name")])
    domains = factory.List([factory.Faker("domain_name")])
    os = fuzzy.FuzzyChoice(OPERATING_SYSTEMS)
    port = fuzzy.FuzzyChoice([22, 80, 443, 3389, 5432, 8080])
    transport = "tcp"
    org = factory.Faker("company")
    isp = factory.Faker("company")
    asn = factory.Faker("bothify", text="AS####")
    product = fuzzy.FuzzyChoice(PRODUCTS)
    version = factory.Faker("numerify", text="#.#.#")
    timestamp = factory.Faker("iso8601")
    location = factory.SubFactory(MatchLocationFactory)
    data = factory.Faker("sentence", nb_words=8)
    vulns = factory.Dict({})


class UsageLimitsFactory(factory.Factory):
    class Meta:
        model = UsageLimits

    scan_credits = 100
    query_credits = 100
    monitored_ips = 16


class ApiInfoFactory(factory.Factory):
    class Meta:
        model = ApiInfo

    scan_credits = 100
    query_credits = 100
    plan = "dev"
    https = False
    unlocked = True
    unlocked_left = 100
    telnet = False
    monitored_ips = 16
    usage_limits = factory.SubFactory(UsageLimitsFactory)
