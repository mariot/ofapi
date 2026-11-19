"""IPsum: the level 5 list of malicious addresses of the stamparm/ipsum repository,
served by the GitHub module (ipsum connector)."""

from app.fake import fake
from app.vendors.github import Repo


def _level_5() -> bytes:
    """One address per line: public hosts, a private one and a /30 the connector
    expands or drops."""
    lines = [fake.ipv4_public() for _ in range(8)]
    lines += ["10.0.0.7", "198.18.0.0/30"]
    return ("\n".join(lines) + "\n").encode()


def _repo() -> Repo:
    return Repo(
        files={"levels/5.txt": _level_5(), "README.md": b"# IPsum\n"},
        branch="master",
        description="Daily feed of bad IPs (with blacklist hit scores)",
    )


GITHUB_REPOS = {"stamparm/ipsum": _repo}
