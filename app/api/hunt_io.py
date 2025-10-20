from dataclasses import asdict, dataclass

import factory
from factory import fuzzy

MALWARE_NAMES = [
	"Keitaro",
	"Tactical RMM",
	"Gophish",
	"Acunetix",
	"ARL",
	"Burp Collaborator",
	"Mozi",
	"Interactsh",
	"Cobalt Strike",
	"Hajime",
	"Cobalt Strike Unverified",
	"Pyramid C2",
	"Metasploit",
	"Mirai",
	"AsyncRAT",
	"Ramnit",
	"Sliver",
	"evilgophish",
	"reNgine",
	"Nessus VA",
	"Havoc",
	"Viper",
	"Supershell",
	"Lumma",
	"Quasar",
	"Mythic",
	"Remcos",
	"Gh0st RAT",
	"ReverseSSH",
	"Metasploit Meterpreter",
	"MITRE Caldera",
	"Hak5 Cloud C2",
	"Redline Stealer",
	"AdaptixC2",
	"Ligolo-ng",
	"DcRat",
	"Latrodectus",
	"DayBreak",
	"XenoRAT",
	"L3MON",
	"Daam",
	"Kaiji",
	"VenomRAT",
	"Chaos RAT",
	"ValleyRAT",
	"Burp Suite",
	"Yakit Security Tool",
	"RedWarden",
	"ShadowPad",
	"OWASP ZAP API",
	"SparkRAT",
	"DarkComet",
	"Moobot",
	"HOOKBOT",
	"Unam",
	"GobRAT",
	"ClayRat",
	"qakbot",
	"Pupy C2",
	"Stealc",
	"Starkiller",
	"X-Ray Vuln Scanner",
	"SectopRAT",
	"SpiceRAT",
	"Brute Ratel C4",
	"Lazarus Group",
	"Kimsuky",
	"Ares",
	"Lazarus Stealer",
	"Covenant",
	"RedJuliett",
	"JS-Tap",
	"HOOKBOT Fork",
	"Chalubo RAT",
]

MALWARE_SUBSYSTEMS = [
	"C2",
	"Exploit Server",
	"Infrastructure",
	"Management",
	"Phishing",
	"Red Team Tools",
	"Redirect",
	"Team Server",
	"Victim",
]


@dataclass
class Malware:
	name: str
	subsystem: str


@dataclass
class C2FeedExtra:
	status_code: int
	geoip_city: str
	geoip_country: str
	geoip_asn: str
	geoip_asn_num: int
	geoip_subnetwork: str
	domain_private_name: str
	domain_type: str


@dataclass
class C2Feed:
	ip: str
	hostname: str
	scan_uri: str
	timestamp: str
	port: int
	malware: Malware
	extra: C2FeedExtra
	confidence: int

	def to_dict(self):
		result = asdict(self)
		result.update({"malware_name": result["malware"].pop("name")})
		result.update({"malware_subsystem": result["malware"].pop("subsystem")})
		result.pop("malware")
		return result


class MalwareFactory(factory.Factory):
	class Meta:
		model = Malware

	name = fuzzy.FuzzyChoice(MALWARE_NAMES)
	subsystem = fuzzy.FuzzyChoice(MALWARE_SUBSYSTEMS)


class C2FeedExtraFactory(factory.Factory):
	class Meta:
		model = C2FeedExtra

	status_code = factory.Faker("random_int", min=100, max=599)
	geoip_city = factory.Faker("city")
	geoip_country = factory.Faker("country")
	geoip_asn = factory.Faker("word")
	geoip_asn_num = factory.Faker("random_int", min=1, max=65535)
	geoip_subnetwork = factory.Faker("ipv4", network=True)
	domain_private_name = factory.Faker("domain_name")
	domain_type = factory.Faker("word")


class C2FeedFactory(factory.Factory):
	class Meta:
		model = C2Feed

	ip = factory.Faker("ipv4")
	hostname = factory.Faker("domain_name")
	scan_uri = factory.Faker("url")
	timestamp = factory.Faker("iso8601")
	port = factory.Faker("random_int", min=1, max=65535)
	confidence = factory.Faker("random_int", min=1, max=100)
	malware = factory.SubFactory(MalwareFactory)
	extra = factory.SubFactory(C2FeedExtraFactory)
