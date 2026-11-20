"""TweetFeed: the daily IOC CSV files of the 0xDanielLopez/TweetFeed repository, served
by the GitHub module (tweetfeed connector). Any day (``YYYY/YYYYMM/YYYYMMDD.csv``) and
``today.csv`` answer a fresh file."""

import re
from datetime import datetime, timedelta

from app.fake import fake
from app.vendors.github import Repo

DAY_FILE = re.compile(r"today\.csv|\d{4}/\d{6}/\d{8}\.csv")
USERS = ["malwrhunterteam", "500mk500", "JAMESWT_MHT", "Cryptolaemus1"]
TAGS = ["#phishing", "#Qakbot", "#exe #malware", "#cobaltstrike", "", "#opendir"]


def _ioc(kind: str) -> str:
    return {
        "ip": fake.ipv4_public(),
        "domain": fake.domain_name(),
        "url": f"https://{fake.domain_name()}/{fake.word()}/{fake.word()}.php",
        "sha256": fake.sha256(),
        "md5": fake.md5(),
    }[kind]


def _csv() -> bytes:
    """Rows are date,user,type,value,tags,tweet; one of each IOC type."""
    rows = []
    for kind, tags in zip(["ip", "domain", "url", "sha256", "md5"], TAGS, strict=False):
        when = datetime.now() - timedelta(hours=fake.random_int(1, 20))
        user = fake.random_element(USERS)
        tweet = f"https://twitter.com/{user}/status/{fake.random_number(18, True)}"
        rows.append(
            f"{when:%Y-%m-%d %H:%M:%S},{user},{kind},{_ioc(kind)},{tags},{tweet}"
        )
    return ("\n".join(rows) + "\n").encode()


class _Files(dict):
    """The files of the repository: the daily CSVs are made when read."""

    def __contains__(self, path) -> bool:
        return bool(DAY_FILE.fullmatch(path)) or super().__contains__(path)

    def __getitem__(self, path) -> bytes:
        if DAY_FILE.fullmatch(path):
            return _csv()
        return super().__getitem__(path)


def _repo() -> Repo:
    return Repo(
        files=_Files({"README.md": b"# TweetFeed\n"}),
        branch="master",
        description="Collecting Indicators of Compromise (IOCs) shared on Twitter",
    )


GITHUB_REPOS = {"0xDanielLopez/TweetFeed": _repo}
