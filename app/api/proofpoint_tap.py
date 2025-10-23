from dataclasses import dataclass

import factory
from factory import fuzzy
from faker import Faker


@dataclass
class Campaign:
    _lastUpdatedAt: str
    id: str
    lastUpdatedAt: str
    notable: bool
    verticallyTargeted: bool


@dataclass
class CampaignMember:
    _threatTime: str
    id: str
    threat: str
    type: str
    subType: str
    threatTime: str
    threatStatus: str


@dataclass
class CampaignItem:
    name: str
    id: str


@dataclass
class Actor(CampaignItem):
    pass


@dataclass
class Malware(CampaignItem):
    pass


@dataclass
class Technique(CampaignItem):
    pass


@dataclass
class CampaignFamily(CampaignItem):
    pass


@dataclass
class CampaignDetail:
    _startDate: str
    id: str
    name: str
    description: str
    startDate: str
    campaignMembers: list[CampaignMember]
    actors: list[Actor]
    malware: list[Malware]
    techniques: list[Technique]


class CampaignFactory(factory.Factory):
    class Meta:
        model = Campaign

    id = factory.Faker("uuid4")
    _lastUpdatedAt = factory.Faker("iso8601")
    lastUpdatedAt = factory.LazyAttribute(lambda o: f"{o._lastUpdatedAt}Z")
    notable = fuzzy.FuzzyChoice([True, False])
    verticallyTargeted = fuzzy.FuzzyChoice([True, False])


class CampaignItemFactory(factory.Factory):
    class Meta:
        model = CampaignItem

    id = factory.Faker("uuid4")
    name = factory.Faker("word")


class ActorFactory(CampaignItemFactory):
    class Meta:
        model = Actor


class MalwareFactory(CampaignItemFactory):
    class Meta:
        model = Malware


class TechniqueFactory(CampaignItemFactory):
    class Meta:
        model = Technique


class CampaignFamilyFactory(CampaignItemFactory):
    class Meta:
        model = CampaignFamily


class CampaignMemberFactory(factory.Factory):
    class Meta:
        model = CampaignMember

    id = factory.Faker("uuid4")
    _threatTime = factory.Faker("iso8601")
    threatTime = factory.LazyAttribute(lambda o: f"{o._threatTime}Z")
    type = fuzzy.FuzzyChoice(["attachment", "url"])
    threat = factory.LazyAttribute(
        lambda o: Faker().md5() if o.type == "attachment" else Faker().uri()
    )
    subType = factory.LazyAttribute(
        lambda o: "ATTACHMENT"
        if o.type == "attachment"
        else fuzzy.FuzzyChoice(
            ["COMPLETE_URL", "NORMALIZED_URL", "HOSTNAME", "DOMAIN"]
        ).fuzz()
    )
    threatStatus = fuzzy.FuzzyChoice(["active", "cleared", "falsePositive"])


class CampaignDetailFactory(factory.Factory):
    class Meta:
        model = CampaignDetail

    id = factory.Faker("uuid4")
    name = factory.Faker("sentence", nb_words=4)
    description = factory.Faker("paragraph", nb_sentences=3)
    _startDate = factory.Faker("iso8601")
    startDate = factory.LazyAttribute(lambda o: f"{o._startDate}Z")
    campaignMembers = factory.List(
        [factory.SubFactory(CampaignMemberFactory) for _ in range(5)]
    )
    actors = factory.List([factory.SubFactory(ActorFactory) for _ in range(2)])
    malware = factory.List([factory.SubFactory(MalwareFactory) for _ in range(2)])
    techniques = factory.List([factory.SubFactory(TechniqueFactory) for _ in range(2)])
