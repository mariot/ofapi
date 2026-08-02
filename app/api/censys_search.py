"""Factories for the Censys Search API v2 (``search.censys.io``).

The Censys *Platform* API (``/censys/v3/...``) is modelled in :mod:`app.api.censys`
with the official ``censys_platform`` models. The Search API v2 is a different,
older API - cursor paginated and with a much flatter payload - so it gets its own
hand-written dataclasses here.
"""

from dataclasses import dataclass

import factory
from factory import fuzzy

SERVICE_NAMES = ["HTTP", "HTTPS", "SSH", "DNS", "FTP", "SMTP", "POSTGRES", "REDIS"]


@dataclass
class HostService:
    port: int
    service_name: str
    transport_protocol: str


@dataclass
class HostLocation:
    country: str
    country_code: str
    city: str


@dataclass
class HostAutonomousSystem:
    asn: int
    name: str
    country_code: str


@dataclass
class HostHit:
    ip: str
    services: list[HostService]
    location: HostLocation
    autonomous_system: HostAutonomousSystem
    last_updated_at: str


@dataclass
class CertificateHit:
    fingerprint_sha256: str
    names: list[str]
    parsed_subject_dn: str
    parsed_issuer_dn: str
    validation_level: str
    added_at: str


class HostServiceFactory(factory.Factory):
    class Meta:
        model = HostService

    port = fuzzy.FuzzyChoice([21, 22, 25, 53, 80, 443, 5432, 6379, 8080, 8443])
    service_name = fuzzy.FuzzyChoice(SERVICE_NAMES)
    transport_protocol = "TCP"


class HostLocationFactory(factory.Factory):
    class Meta:
        model = HostLocation

    country = factory.Faker("country")
    country_code = factory.Faker("country_code")
    city = factory.Faker("city")


class HostAutonomousSystemFactory(factory.Factory):
    class Meta:
        model = HostAutonomousSystem

    asn = factory.Faker("random_int", min=1, max=65535)
    name = factory.Faker("company")
    country_code = factory.Faker("country_code")


class HostHitFactory(factory.Factory):
    class Meta:
        model = HostHit

    ip = factory.Faker("ipv4_public")
    services = factory.List([factory.SubFactory(HostServiceFactory) for _ in range(3)])
    location = factory.SubFactory(HostLocationFactory)
    autonomous_system = factory.SubFactory(HostAutonomousSystemFactory)
    last_updated_at = factory.Faker("iso8601")


class CertificateHitFactory(factory.Factory):
    class Meta:
        model = CertificateHit

    fingerprint_sha256 = factory.Faker("sha256")
    names = factory.List([factory.Faker("domain_name") for _ in range(2)])
    parsed_subject_dn = factory.Faker("sentence", nb_words=3)
    parsed_issuer_dn = factory.Faker("sentence", nb_words=4)
    validation_level = fuzzy.FuzzyChoice(["DV", "OV", "EV"])
    added_at = factory.Faker("iso8601")
