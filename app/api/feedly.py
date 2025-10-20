from dataclasses import dataclass, asdict

import factory


def _remove_private_attributes(data_dict: dict) -> dict:
    """
    Removes keys starting with an underscore from a dictionary.
    """
    return {key: value for key, value in data_dict.items() if not key.startswith("_")}


@dataclass
class StixItem:
    _internal_id: str
    id: str
    type: str
    spec_version: str


@dataclass
class DomainName(StixItem):
    value: str


@dataclass
class Url(StixItem):
    value: str


@dataclass
class Ipv4Addr(StixItem):
    value: str


@dataclass
class StixItemWithDates(StixItem):
    _created: str
    _modified: str
    created: str
    modified: str

@dataclass
class Indicator(StixItemWithDates):
    _file_hash: str
    pattern: str
    name: str
    _valid_from: str
    valid_from: str
    pattern_type: str = "stix"
    pattern_version: str = "2.1"


@dataclass
class Source:
    source_name: str
    url: str


@dataclass
class Malware(StixItemWithDates):
    name: str
    description: str
    is_family: bool
    aliases: list[str]
    external_references: list[Source]


@dataclass
class Report(StixItemWithDates):
    name: str
    description: str
    _published: str
    published: str
    object_refs: list[StixItem]
    external_references: list[Source]
    context = "unspecified"


@dataclass
class Bundle(StixItem):
    reports: list[Report]

    def to_dict(self):
        bundle = _remove_private_attributes(asdict(self))
        reports = self.reports
        bundle.pop("reports")
        bundle.pop("spec_version")
        bundle["objects"] = []
        for report in reports:
            report = _remove_private_attributes(asdict(report))
            object_refs = report.pop("object_refs")
            report["object_refs"] = [obj["id"] for obj in object_refs]
            bundle["objects"].append(report)
            for linked_obj in object_refs:
                bundle["objects"].append(_remove_private_attributes(linked_obj))
        return bundle

class StixItemFactory(factory.Factory):
    class Meta:
        model = StixItem

    _internal_id = factory.Faker("uuid4")
    type = factory.Faker("word")
    id = factory.LazyAttribute(lambda o: f"{o.type}--{o._internal_id}")
    spec_version = "2.1"

class DomainNameFactory(StixItemFactory):
    class Meta:
        model = DomainName

    type = "domain-name"
    value = factory.Faker("domain_name")

class UrlFactory(StixItemFactory):
    class Meta:
        model = Url

    type = "url"
    value = factory.Faker("url")

class Ipv4AddrFactory(StixItemFactory):
    class Meta:
        model = Ipv4Addr

    type = "ipv4-addr"
    value = factory.Faker("ipv4")


class StixItemFactoryWithDates(StixItemFactory):
    class Meta:
        model = StixItemWithDates

    _created = factory.Faker("iso8601")
    _modified = factory.Faker("iso8601")
    created = factory.LazyAttribute(lambda o: f"{o._created}Z")
    modified = factory.LazyAttribute(lambda o: f"{o._modified}Z")


class IndicatorFactory(StixItemFactoryWithDates):
    class Meta:
        model = Indicator

    _file_hash = factory.Faker("md5")
    type = "indicator"
    pattern = factory.LazyAttribute(lambda o: f"[file:hashes.MD5 = '{o._file_hash}']")
    name = "Hash"
    _valid_from = factory.Faker("iso8601")
    valid_from = factory.LazyAttribute(lambda o: f"{o._valid_from}Z")


class SourceFactory(factory.Factory):
    class Meta:
        model = Source

    source_name = factory.Faker("company")
    url = factory.Faker("uri")

class MalwareFactory(StixItemFactoryWithDates):
    class Meta:
        model = Malware

    type = "malware"
    name = factory.Faker("word")
    description = factory.Faker("paragraph", nb_sentences=3)
    is_family = factory.Faker("boolean")
    aliases = factory.List([factory.Faker("word") for _ in range(3)])
    external_references = factory.List([factory.SubFactory(SourceFactory) for _ in range(2)])


class ReportFactory(StixItemFactoryWithDates):
    class Meta:
        model = Report

    type = "report"
    name = factory.Faker("sentence", nb_words=6)
    description = factory.Faker("paragraph")
    _published = factory.Faker("iso8601")
    published = factory.LazyAttribute(lambda o: f"{o._published}Z")
    external_references = factory.List([factory.SubFactory(SourceFactory) for _ in range(2)])
    object_refs = factory.List(
        [
            factory.SubFactory(MalwareFactory),
            factory.SubFactory(IndicatorFactory),
            factory.SubFactory(UrlFactory),
            factory.SubFactory(DomainNameFactory),
            factory.SubFactory(Ipv4AddrFactory),
        ]
    )


class BundleFactory(StixItemFactory):
    class Meta:
        model = Bundle

    type = "bundle"
    reports = factory.List([factory.SubFactory(ReportFactory) for _ in range(3)])
