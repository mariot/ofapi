"""GitHub: public repositories, read by the OpenCTI cvelistv5,
cyber-campaign-collection and disarm-framework connectors (and any connector reading
public data from GitHub).

Every GitHub host answers here and is told apart by the original host the proxy sends:

* ``github.com``: git clone/fetch over the dumb HTTP protocol
  (``/<owner>/<repo>.git/...``), archives (``/<owner>/<repo>/archive/<ref>.zip``),
  raw files, release downloads.
* ``api.github.com``: ``/repos/<owner>/<repo>`` and its contents, git trees and blobs,
  branches, commits, tags, releases, zipball and tarball (PyGithub, REST clients).
* ``raw.githubusercontent.com``: ``/<owner>/<repo>/<ref>/<path>``.
* ``codeload.github.com``: ``/<owner>/<repo>/zip|tar.gz|legacy.zip/<ref>``.

A repository is a ``Repo``: its files (path -> bytes), default branch, latest release
tag and release assets. Built-in repositories are in ``BUILTIN``; another vendor module
serves its own by exposing ``GITHUB_REPOS = {"owner/repo": Repo(...) or a function
returning one}``, which this module finds on every request (names are
case-insensitive). Unknown repositories answer 404.
"""

import hashlib
import io
import json
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import zipfile
from base64 import b64encode
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse

from app.fake import fake

HOSTS = [
    "github.com",
    "www.github.com",
    "api.github.com",
    "raw.githubusercontent.com",
    "codeload.github.com",
]
router = APIRouter(prefix="/github", tags=["GitHub"])

API = "https://api.github.com"
RAW = "https://raw.githubusercontent.com"
BARE_REPOS: dict[str, Path] = {}
BUILT: dict[str, Repo] = {}


@dataclass
class Repo:
    files: dict[str, bytes]
    branch: str = "main"
    tag: str = "v1.0.0"
    description: str = ""
    assets: dict[str, bytes] = field(default_factory=dict)


def _record(cve_id: str, year: int, state: str = "PUBLISHED") -> dict:
    """A CVE Record Format 5.1 document, as published in CVEProject/cvelistV5."""
    published = datetime.now(UTC).replace(microsecond=0)
    published = published.replace(day=1).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    metadata = {
        "cveId": cve_id,
        "assignerOrgId": fake.uuid4(),
        "state": state,
        "assignerShortName": "mitre",
        "dateReserved": published,
        "datePublished": published,
        "dateUpdated": published,
    }
    if state != "PUBLISHED":
        return {
            "dataType": "CVE_RECORD",
            "dataVersion": "5.1",
            "cveMetadata": metadata,
            "containers": {
                "cna": {"rejectedReasons": [{"lang": "en", "value": "n/a"}]}
            },
        }
    vendor, product = fake.company().split(",")[0], fake.word().capitalize()
    cwe = fake.cwe_id()
    cna = {
        "providerMetadata": {"orgId": metadata["assignerOrgId"], "shortName": "mitre"},
        "title": f"{vendor} {product} vulnerability",
        "descriptions": [
            {
                "lang": "en",
                "value": f"{product} before 4.2 allows remote code execution.",
            },
            {
                "lang": "es",
                "value": f"{product} anterior a 4.2 permite ejecucion remota.",
            },
        ],
        "affected": [
            {
                "vendor": vendor,
                "product": product,
                "versions": [
                    {"version": "0", "status": "affected", "lessThan": "4.2"},
                    {"version": "4.2", "status": "unaffected"},
                ],
            },
            {
                "vendor": vendor,
                "product": f"{product} Server",
                "cpes": [fake.cpe23(), fake.cpe23()],
            },
        ],
        "problemTypes": [
            {
                "descriptions": [
                    {
                        "lang": "en",
                        "type": "CWE",
                        "cweId": cwe,
                        "description": f"{cwe} Improper Input Validation",
                    }
                ]
            }
        ],
        "references": [
            {
                "url": f"https://{fake.domain_name()}/advisory/{cve_id}",
                "name": "vendor",
            },
            {
                "url": f"https://{fake.domain_name()}/blog/{year}",
                "tags": ["third-party"],
            },
        ],
        "workarounds": [{"lang": "en", "value": "Disable the affected module."}],
        "solutions": [{"lang": "en", "value": f"Upgrade {product} to 4.2 or later."}],
        "exploits": [{"lang": "en", "value": "A public proof of concept exists."}],
        "configurations": [
            {"lang": "en", "value": "Only the default install is affected."}
        ],
        "metrics": [
            {
                "format": "CVSS",
                "cvssV3_1": {
                    "version": "3.1",
                    "baseScore": 9.8,
                    "baseSeverity": "CRITICAL",
                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "attackVector": "NETWORK",
                    "attackComplexity": "LOW",
                    "privilegesRequired": "NONE",
                    "userInteraction": "NONE",
                    "scope": "UNCHANGED",
                    "confidentialityImpact": "HIGH",
                    "integrityImpact": "HIGH",
                    "availabilityImpact": "HIGH",
                },
            }
        ],
    }
    adp = {
        "providerMetadata": {"orgId": fake.uuid4(), "shortName": "CISA-ADP"},
        "title": "CISA ADP Vulnrichment",
        "metrics": [{"other": {"type": "ssvc", "content": {"id": cve_id}}}],
    }
    return {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.1",
        "cveMetadata": metadata,
        "containers": {"cna": cna, "adp": [adp]},
    }


def _cvelist() -> Repo:
    """cves/<year>/<n>xxx/CVE-<year>-<n>.json, the layout of CVEProject/cvelistV5."""
    year = datetime.now(UTC).year
    files = {
        "README.md": b"# cvelistV5\n",
        "cves/delta.json": b"{}",
        "cves/deltaLog.json": b"[]",
    }
    records = [
        *[(f"CVE-{year}-{1000 + n}", year, "PUBLISHED") for n in range(6)],
        (f"CVE-{year}-2000", year, "REJECTED"),
        (f"CVE-{year - 1}-3000", year - 1, "PUBLISHED"),
        ("CVE-2010-4000", 2010, "PUBLISHED"),
    ]
    for cve_id, record_year, state in records:
        number = int(cve_id.rsplit("-", 1)[1])
        path = f"cves/{record_year}/{number // 1000}xxx/{cve_id}.json"
        files[path] = json.dumps(_record(cve_id, record_year, state), indent=2).encode()
    return Repo(files, branch="main", description="CVE Record Format JSON files")


def _pdf(title: str) -> bytes:
    return (
        b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
        b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
        b"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 200 200]>>endobj\n"
        + f"% {title}\n".encode()
        + b"trailer<</Root 1 0 R>>\n%%EOF\n"
    )


def _campaigns() -> Repo:
    """<year>/<yyyy.mm.dd_Report_Name>/<files>: the APT and cybercriminal reports."""
    files = {"README.md": b"# APT & CyberCriminal Campaign Collections\n"}
    now = datetime.now(UTC)
    for year in {now.year - 1, now.year}:
        for month, day, name in (
            (1, 12, "Operation_Ghost_Courier"),
            (1, 28, "APT-Spring_Dragon_Targets_Telecom"),
            (0, 0, "Undated_Report_On_Loader"),
        ):
            folder = f"{year}/{year}.{month:02d}.{day:02d}_{name}"
            files[f"{folder}/{name}.pdf"] = _pdf(name)
            files[f"{folder}/README.md"] = f"# {name}\n".encode()
    return Repo(files, branch="master", description="Campaign collections")


def _disarm() -> Repo:
    """generated_files/DISARM_STIX/DISARM.json: the DISARM STIX 2.1 bundle."""
    now = "2024-06-01T00:00:00.000Z"
    identity = {
        "type": "identity",
        "spec_version": "2.1",
        "id": "identity--b2f6d9c1-0e0b-5f3a-9a64-6b0b1b7d8d11",
        "created": now,
        "modified": now,
        "name": "DISARM Foundation",
        "identity_class": "organization",
    }
    marking = {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
        "created": "2017-01-20T00:00:00.000Z",
        "definition_type": "tlp",
        "name": "TLP:CLEAR",
        "definition": {"tlp": "clear"},
    }

    def common(kind: str, name: str, **extra) -> dict:
        return {
            "type": kind,
            "spec_version": "2.1",
            "id": f"{kind}--{fake.uuid4()}",
            "created": now,
            "modified": now,
            "name": name,
            "created_by_ref": identity["id"],
            "object_marking_refs": [marking["id"]],
            **extra,
        }

    phases = ["plan-strategy", "plan-objectives", "develop-content", "deliver-content"]
    patterns = [
        common(
            "attack-pattern",
            name,
            description=f"{name}: a DISARM technique.",
            kill_chain_phases=[
                {"kill_chain_name": "disarm", "phase_name": phases[i % 4]}
            ],
            external_references=[
                {
                    "source_name": "DISARM",
                    "external_id": f"T00{i:02d}",
                    "url": f"https://disarmframework.herokuapp.com/techniques/T00{i:02d}",
                }
            ],
        )
        for i, name in enumerate(
            [
                "Create fake experts",
                "Flood information space",
                "Amplify via bots",
                "Hijack hashtags",
            ]
        )
    ]
    actor = common("intrusion-set", "Storm-1516", aliases=["Doppelganger"])
    campaign = common("campaign", "Operation Overload")
    malware = common("malware", "FakeNewsBot", is_family=True)
    tool = common("tool", "Social Amplifier")
    course = common(
        "course-of-action", "Prebunking", description="Inoculate audiences."
    )
    narrative = common(
        "narrative", "Election was stolen", description="A recurring narrative."
    )
    event = common("event", "Election day", description="National election.")
    channel = common("channel", "Telegram channel", description="A broadcast channel.")
    objects = [
        identity,
        marking,
        *patterns,
        actor,
        campaign,
        malware,
        tool,
        course,
        narrative,
        event,
        channel,
    ]
    for kind, target in (("uses", patterns[0]), ("uses", patterns[1]), ("uses", tool)):
        objects.append(
            {
                "type": "relationship",
                "spec_version": "2.1",
                "id": f"relationship--{fake.uuid4()}",
                "created": now,
                "modified": now,
                "relationship_type": kind,
                "source_ref": actor["id"],
                "target_ref": target["id"],
                "created_by_ref": identity["id"],
            }
        )
    objects.append(
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": f"relationship--{fake.uuid4()}",
            "created": now,
            "modified": now,
            "relationship_type": "mitigates",
            "source_ref": course["id"],
            "target_ref": patterns[2]["id"],
            "created_by_ref": identity["id"],
        }
    )
    objects.append(
        common(
            "report",
            "DISARM red framework",
            published=now,
            report_types=["threat-report"],
            object_refs=[patterns[0]["id"], actor["id"], campaign["id"]],
        )
    )
    bundle = {"type": "bundle", "id": f"bundle--{fake.uuid4()}", "objects": objects}
    path = "generated_files/DISARM_STIX/DISARM.json"
    return Repo({path: json.dumps(bundle, indent=2).encode()}, branch="main")


BUILTIN: dict[str, Callable[[], Repo]] = {
    "cveproject/cvelistv5": _cvelist,
    "cybermonitor/apt_cybercriminal_campagin_collections": _campaigns,
    "disarmfoundation/disarmframeworks": _disarm,
}


def _repository(full_name: str) -> Repo | None:
    """The repository, from ``GITHUB_REPOS`` of the vendor modules or the built-ins."""
    key = full_name.lower()
    if key in BUILT:
        return BUILT[key]
    sources = [BUILTIN]
    for name, module in list(sys.modules.items()):
        if name.startswith("app.vendors.") and name != __name__:
            sources.append(
                {k.lower(): v for k, v in getattr(module, "GITHUB_REPOS", {}).items()}
            )
    for source in reversed(sources):
        if key in source:
            made = source[key]
            BUILT[key] = made() if callable(made) else made
            return BUILT[key]
    return None


def _blob_sha(data: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()  # noqa: S324


def _head_sha(repo: Repo) -> str:
    digest = hashlib.sha1()  # noqa: S324
    for path in sorted(repo.files):
        digest.update(path.encode() + _blob_sha(repo.files[path]).encode())
    return digest.hexdigest()


def _ref_name(ref: str) -> str:
    for prefix in ("refs/heads/", "refs/tags/"):
        ref = ref.removeprefix(prefix)
    return ref


def _not_found(message: str = "Not Found") -> JSONResponse:
    return JSONResponse(
        {"message": message, "documentation_url": "https://docs.github.com/rest"},
        status_code=404,
    )


def _owner(login: str) -> dict:
    return {
        "login": login,
        "id": 1000 + len(login),
        "type": "Organization",
        "url": f"{API}/users/{login}",
        "html_url": f"https://github.com/{login}",
        "avatar_url": f"https://avatars.githubusercontent.com/u/{1000 + len(login)}",
    }


def _repo_json(full_name: str, repo: Repo) -> dict:
    owner, name = full_name.split("/", 1)
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "id": 100000 + len(full_name),
        "name": name,
        "full_name": full_name,
        "private": False,
        "owner": _owner(owner),
        "html_url": f"https://github.com/{full_name}",
        "description": repo.description,
        "fork": False,
        "url": f"{API}/repos/{full_name}",
        "git_url": f"git://github.com/{full_name}.git",
        "clone_url": f"https://github.com/{full_name}.git",
        "default_branch": repo.branch,
        "created_at": "2018-01-01T00:00:00Z",
        "updated_at": now,
        "pushed_at": now,
        "size": sum(len(v) for v in repo.files.values()) // 1024 + 1,
        "archived": False,
        "disabled": False,
        "visibility": "public",
    }


def _entry(full_name: str, repo: Repo, path: str, ref: str, *, is_dir: bool) -> dict:
    """An item of the contents API."""
    data = b"" if is_dir else repo.files[path]
    kind = "dir" if is_dir else "file"
    api = f"{API}/repos/{full_name}/contents/{path}"
    html_kind = "tree" if is_dir else "blob"
    entry = {
        "type": kind,
        "name": PurePosixPath(path).name,
        "path": path,
        "sha": _head_sha(repo) if is_dir else _blob_sha(data),
        "size": len(data),
        "url": f"{api}?ref={ref}",
        "html_url": f"https://github.com/{full_name}/{html_kind}/{ref}/{path}",
        "git_url": f"{API}/repos/{full_name}/git/{'trees' if is_dir else 'blobs'}/"
        + (_head_sha(repo) if is_dir else _blob_sha(data)),
        "download_url": None if is_dir else f"{RAW}/{full_name}/{ref}/{path}",
        "_links": {"self": f"{api}?ref={ref}"},
    }
    return entry


def _children(repo: Repo, path: str) -> list[tuple[str, bool]]:
    """Direct children of a directory: (path, is directory), sorted by name."""
    prefix = f"{path}/" if path else ""
    found: dict[str, bool] = {}
    for name in repo.files:
        if not name.startswith(prefix):
            continue
        head, _, rest = name[len(prefix) :].partition("/")
        found[prefix + head] = bool(rest) or found.get(prefix + head, False)
    return sorted(found.items())


def _contents(full_name: str, repo: Repo, path: str, ref: str) -> Response:
    path = path.strip("/")
    if path in repo.files:
        data = repo.files[path]
        item = _entry(full_name, repo, path, ref, is_dir=False)
        item["content"] = b64encode(data).decode()
        item["encoding"] = "base64"
        return JSONResponse(item)
    children = _children(repo, path)
    if not children:
        return _not_found()
    return JSONResponse(
        [_entry(full_name, repo, p, ref, is_dir=d) for p, d in children]
    )


def _tree(full_name: str, repo: Repo) -> dict:
    entries = []
    folders = {
        "/".join(parts[:i])
        for name in repo.files
        for parts in [name.split("/")]
        for i in range(1, len(parts))
    }
    for folder in sorted(folders):
        sha = hashlib.sha1(folder.encode()).hexdigest()  # noqa: S324
        entries.append(
            {
                "path": folder,
                "mode": "040000",
                "type": "tree",
                "sha": sha,
                "url": f"{API}/repos/{full_name}/git/trees/{sha}",
            }
        )
    for name, data in sorted(repo.files.items()):
        sha = _blob_sha(data)
        entries.append(
            {
                "path": name,
                "mode": "100644",
                "type": "blob",
                "sha": sha,
                "size": len(data),
                "url": f"{API}/repos/{full_name}/git/blobs/{sha}",
            }
        )
    sha = _head_sha(repo)
    return {
        "sha": sha,
        "url": f"{API}/repos/{full_name}/git/trees/{sha}",
        "tree": entries,
        "truncated": False,
    }


def _commit(full_name: str, repo: Repo) -> dict:
    sha = _head_sha(repo)
    when = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    person = {"name": "staticfire", "email": "staticfire@example.com", "date": when}
    return {
        "sha": sha,
        "url": f"{API}/repos/{full_name}/commits/{sha}",
        "html_url": f"https://github.com/{full_name}/commit/{sha}",
        "commit": {"author": person, "committer": person, "message": "Update records"},
        "parents": [],
    }


def _release(full_name: str, repo: Repo) -> dict:
    when = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    base = f"https://github.com/{full_name}/releases/download/{repo.tag}"
    return {
        "id": 1,
        "tag_name": repo.tag,
        "name": repo.tag,
        "draft": False,
        "prerelease": False,
        "created_at": when,
        "published_at": when,
        "html_url": f"https://github.com/{full_name}/releases/tag/{repo.tag}",
        "zipball_url": f"{API}/repos/{full_name}/zipball/{repo.tag}",
        "tarball_url": f"{API}/repos/{full_name}/tarball/{repo.tag}",
        "body": "",
        "assets": [
            {
                "id": i,
                "name": name,
                "size": len(data),
                "state": "uploaded",
                "content_type": "application/octet-stream",
                "browser_download_url": f"{base}/{name}",
                "url": f"{API}/repos/{full_name}/releases/assets/{i}",
            }
            for i, (name, data) in enumerate(sorted(repo.assets.items()), start=1)
        ],
    }


def _archive(full_name: str, repo: Repo, ref: str, kind: str) -> Response:
    root = f"{full_name.split('/', 1)[1]}-{_ref_name(ref)}"
    if kind == "zip":
        out = io.BytesIO()
        with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as archive:
            for name, data in sorted(repo.files.items()):
                archive.writestr(f"{root}/{name}", data)
        return Response(out.getvalue(), media_type="application/zip")
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w:gz") as archive:
        for name, data in sorted(repo.files.items()):
            info = tarfile.TarInfo(f"{root}/{name}")
            info.size, info.mtime = len(data), int(time.time())
            archive.addfile(info, io.BytesIO(data))
    return Response(out.getvalue(), media_type="application/gzip")


def _bare(full_name: str, repo: Repo) -> Path:
    """A bare git repository of the files, ready for the dumb HTTP protocol."""
    key = full_name.lower()
    if key in BARE_REPOS and BARE_REPOS[key].exists():
        return BARE_REPOS[key]
    root = Path(tempfile.mkdtemp(prefix="ofapi-github-")).resolve()
    work, bare = root / "work", root / "bare.git"
    env = {
        "GIT_AUTHOR_NAME": "staticfire",
        "GIT_AUTHOR_EMAIL": "staticfire@example.com",
        "GIT_COMMITTER_NAME": "staticfire",
        "GIT_COMMITTER_EMAIL": "staticfire@example.com",
        "PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin",
        "HOME": str(root),
    }

    def git(*args: str, cwd: Path = work) -> None:
        subprocess.run(
            ["git", *args], cwd=cwd, env=env, check=True, capture_output=True
        )

    work.mkdir()
    git("init", "-b", repo.branch)
    for name, data in repo.files.items():
        target = work / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    git("add", "-A")
    git("commit", "-m", "Update records")
    git("clone", "--bare", str(work), str(bare), cwd=root)
    git("repack", "-a", "-d", cwd=bare)
    git("update-server-info", cwd=bare)
    shutil.rmtree(work)
    BARE_REPOS[key] = bare
    return bare


def _git_http(full_name: str, repo: Repo, rest: str) -> Response:
    bare = _bare(full_name, repo)
    target = (bare / rest).resolve()
    if not target.is_relative_to(bare) or not target.is_file():
        return Response("not found", status_code=404, media_type="text/plain")
    return Response(target.read_bytes(), media_type="application/octet-stream")


def _api(parts: list[str], query: dict) -> Response:
    if len(parts) < 3 or parts[0] != "repos":
        return _not_found()
    full_name = f"{parts[1]}/{parts[2]}"
    repo = _repository(full_name)
    if repo is None:
        return _not_found()
    rest = parts[3:]
    ref = query.get("ref") or repo.branch
    if not rest:
        return JSONResponse(_repo_json(full_name, repo))
    match rest[0]:
        case "contents":
            return _contents(full_name, repo, "/".join(rest[1:]), ref)
        case "git" if rest[1:2] == ["trees"]:
            return JSONResponse(_tree(full_name, repo))
        case "git" if rest[1:2] == ["blobs"]:
            for data in repo.files.values():
                if _blob_sha(data) == rest[2]:
                    return JSONResponse(
                        {
                            "sha": rest[2],
                            "size": len(data),
                            "encoding": "base64",
                            "content": b64encode(data).decode(),
                        }
                    )
            return _not_found()
        case "git" if rest[1:2] == ["ref"] or rest[1:2] == ["refs"]:
            sha = _head_sha(repo)
            return JSONResponse(
                {
                    "ref": f"refs/heads/{repo.branch}",
                    "object": {
                        "type": "commit",
                        "sha": sha,
                        "url": f"{API}/repos/{full_name}/git/commits/{sha}",
                    },
                }
            )
        case "branches":
            sha = _head_sha(repo)
            branch = {
                "name": repo.branch,
                "commit": _commit(full_name, repo),
                "protected": False,
            }
            return JSONResponse(
                branch if len(rest) > 1 else [branch | {"commit": {"sha": sha}}]
            )
        case "commits":
            commit = _commit(full_name, repo)
            return JSONResponse(commit if len(rest) > 1 else [commit])
        case "tags":
            return JSONResponse(
                [
                    {
                        "name": repo.tag,
                        "commit": {"sha": _head_sha(repo)},
                        "zipball_url": f"{API}/repos/{full_name}/zipball/{repo.tag}",
                        "tarball_url": f"{API}/repos/{full_name}/tarball/{repo.tag}",
                    }
                ]
            )
        case "releases":
            release = _release(full_name, repo)
            if rest[1:2] == ["latest"] or rest[1:3] == ["tags", repo.tag]:
                return JSONResponse(release)
            return JSONResponse([release]) if len(rest) == 1 else _not_found()
        case "zipball" | "tarball":
            kind = "zip" if rest[0] == "zipball" else "tar"
            return _archive(full_name, repo, "/".join(rest[1:]) or repo.branch, kind)
    return _not_found()


def _raw(parts: list[str]) -> Response:
    if len(parts) < 4:
        return Response("404: Not Found", status_code=404, media_type="text/plain")
    repo = _repository(f"{parts[0]}/{parts[1]}")
    rest = parts[2:]
    if rest[0] == "refs" and len(rest) > 3:  # refs/heads/<branch>/<path>
        rest = rest[2:]
    path = "/".join(rest[1:])
    if repo is None or path not in repo.files:
        return Response("404: Not Found", status_code=404, media_type="text/plain")
    return Response(repo.files[path], media_type=_mime(path))


def _mime(path: str) -> str:
    return {
        "json": "application/json; charset=utf-8",
        "md": "text/plain; charset=utf-8",
        "txt": "text/plain; charset=utf-8",
        "csv": "text/plain; charset=utf-8",
        "pdf": "application/pdf",
    }.get(path.rsplit(".", 1)[-1].lower(), "application/octet-stream")


def _archive_path(parts: list[str]) -> Response:
    """``<repo>/archive/<ref>.zip`` (github.com), ``.../zip/<ref>`` (codeload)."""
    repo = _repository(f"{parts[0]}/{parts[1]}")
    if repo is None:
        return _not_found()
    rest = parts[3:]
    kind = parts[2]
    if kind == "archive" and rest:
        ref = "/".join(rest)
        for suffix, name in ((".zip", "zip"), (".tar.gz", "tar")):
            if ref.endswith(suffix):
                return _archive(
                    f"{parts[0]}/{parts[1]}", repo, ref.removesuffix(suffix), name
                )
        return _not_found()
    name = "zip" if "zip" in kind else "tar"
    return _archive(f"{parts[0]}/{parts[1]}", repo, "/".join(rest) or repo.branch, name)


@router.api_route("/{path:path}", methods=["GET", "HEAD"])
async def serve(path: str, request: Request) -> Response:
    """Dispatch by the host the client asked for (set by the proxy)."""
    parts = [p for p in path.split("/") if p]
    host = request.headers.get("x-original-host", "").lower()
    if not host:
        if parts[:1] == ["repos"]:
            host = "api.github.com"
        elif len(parts) > 1 and parts[1].endswith(".git"):
            host = "github.com"
        else:
            host = "raw.githubusercontent.com"
    query = dict(request.query_params)
    if host == "api.github.com":
        return _api(parts, query)
    if host == "raw.githubusercontent.com":
        return _raw(parts)
    if host == "codeload.github.com":
        return _archive_path(parts) if len(parts) > 2 else _not_found()
    if len(parts) < 2:
        return Response("not found", status_code=404, media_type="text/plain")
    if parts[1].endswith(".git"):
        full_name = f"{parts[0]}/{parts[1].removesuffix('.git')}"
        repo = _repository(full_name)
        if repo is None:
            return Response("not found", status_code=404, media_type="text/plain")
        return _git_http(full_name, repo, "/".join(parts[2:]))
    if len(parts) > 3 and parts[2] in (
        "archive",
        "zip",
        "tar.gz",
        "legacy.zip",
        "legacy.tar.gz",
    ):
        return _archive_path(parts)
    if len(parts) > 3 and parts[2] in ("raw", "blob"):
        return _raw([parts[0], parts[1], *parts[3:]])
    if len(parts) > 5 and parts[2:4] == ["releases", "download"]:
        repo = _repository(f"{parts[0]}/{parts[1]}")
        name = "/".join(parts[5:])
        if repo and name in repo.assets:
            return Response(repo.assets[name], media_type="application/octet-stream")
    return Response("not found", status_code=404, media_type="text/plain")
