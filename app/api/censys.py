from datetime import timezone

from censys_platform import (
    Attribute,
    BasicConstraints,
    Certificate,
    CertificateExtensions,
    CertificateParsed,
    CertificatePolicy,
    Coordinates,
    ExtendedKeyUsage,
    Host,
    HostDNS,
    KeyAlgorithm,
    KeyUsage,
    Location,
    Routing,
    Service,
    Signature,
    SubjectKeyInfo,
    ValidityPeriod,
)
from factory import (
    Factory,
    Faker,
    List,
    Sequence,
    SubFactory,
    fuzzy,
)


class CoordinatesFactory(Factory):
    class Meta:
        model = Coordinates

    latitude = Faker("latitude")
    longitude = Faker("longitude")


class LocationFactory(Factory):
    class Meta:
        model = Location

    city = Faker("city")
    continent = fuzzy.FuzzyChoice(
        [
            "Africa",
            "Antarctica",
            "Asia",
            "Europe",
            "North America",
            "Oceania",
            "South America",
        ]
    )
    coordinates = SubFactory(CoordinatesFactory)
    country = Faker("country")
    province = Faker("state")


class HostDNSFactory(Factory):
    class Meta:
        model = HostDNS

    names = List([Faker("domain_name"), Faker("domain_name")])


class RoutingFactory(Factory):
    class Meta:
        model = Routing

    asn = Faker("random_int", min=1, max=65535)
    bgp_prefix = Faker("ipv4")
    country_code = Faker("country_code")
    description = Faker("company")
    name = Faker("company")


class KeyAlgorithmFactory(Factory):
    class Meta:
        model = KeyAlgorithm

    name = Faker("word")


class SignatureFactory(Factory):
    class Meta:
        model = Signature

    signature_algorithm = SubFactory(KeyAlgorithmFactory)


class ValidityPeriodFactory(Factory):
    class Meta:
        model = ValidityPeriod

    not_before = Faker("iso8601", tzinfo=timezone.utc)
    not_after = Faker("iso8601", tzinfo=timezone.utc)


class SubjectKeyInfoFactory(Factory):
    class Meta:
        model = SubjectKeyInfo

    key_algorithm = SubFactory(KeyAlgorithmFactory)


class CertificatePolicyFactory(Factory):
    class Meta:
        model = CertificatePolicy

    cps = List([Faker("uri"), Faker("uri")])
    id = Faker("bothify", text="2.23.140.1.2.?")


class KeyUsageFactory(Factory):
    class Meta:
        model = KeyUsage


class BasicConstraintsFactory(Factory):
    class Meta:
        model = BasicConstraints


class ExtendedKeyUsageFactory(Factory):
    class Meta:
        model = ExtendedKeyUsage


class CertificateExtensionsFactory(Factory):
    class Meta:
        model = CertificateExtensions

    key_usage = SubFactory(KeyUsageFactory)
    basic_constraints = SubFactory(BasicConstraintsFactory)
    crl_distribution_points = List([Faker("uri"), Faker("uri")])
    authority_key_id = Faker("sha1")
    extended_key_usage = SubFactory(ExtendedKeyUsageFactory)
    certificate_policies = List([SubFactory(CertificatePolicyFactory)])


class CertificateParsedFactory(Factory):
    class Meta:
        model = CertificateParsed

    serial_number = Sequence(lambda n: str(100000000 + n))
    issuer_dn = Faker("sentence", nb_words=6)
    subject_dn = Faker("sentence", nb_words=3)
    signature = SubFactory(SignatureFactory)
    validity_period = SubFactory(ValidityPeriodFactory)
    subject_key_info = SubFactory(SubjectKeyInfoFactory)
    extensions = SubFactory(CertificateExtensionsFactory)


class CertificateFactory(Factory):
    class Meta:
        model = Certificate

    fingerprint_md5 = Faker("md5")
    fingerprint_sha1 = Faker("sha1")
    fingerprint_sha256 = Faker("sha256")
    parsed = SubFactory(CertificateParsedFactory)


class AttributeFactory(Factory):
    class Meta:
        model = Attribute

    product = Faker("word")
    vendor = Faker("company")
    cpe = Faker("bothify", text="cpe:2.3:a:?????:*:*:*:*:*:*:*:*")


class ServiceFactory(Factory):
    class Meta:
        model = Service

    banner = Faker("sentence", nb_words=4)
    cert = SubFactory(CertificateFactory)
    port = Faker("random_int", min=1, max=65535)
    scan_time = Faker("iso8601", tzinfo=timezone.utc)
    software = List([SubFactory(AttributeFactory)])


class HostFactory(Factory):
    def __new__(cls, *args, **kwargs) -> Host:
        return super().__new__(*args, **kwargs)

    class Meta:
        model = Host

    ip = Faker("ipv4")
    location = SubFactory(LocationFactory)
    dns = SubFactory(HostDNSFactory)
    autonomous_system = SubFactory(RoutingFactory)
    services = List([ServiceFactory(), ServiceFactory()])
