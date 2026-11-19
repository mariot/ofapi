"""CAPEv2 sandbox: tasks, reports and payload archives, read by the cape (import) and
cape-sandbox (enrichment) connectors."""

import struct
import zlib
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Response
from fastapi.responses import JSONResponse

from app.fake import fake

HOSTS = ["cape.example.com"]
router = APIRouter(prefix="/cape", tags=["CAPE"])

FAMILIES = ["Emotet", "Qakbot", "AgentTesla", "Lumma"]
ZIP_PASSWORD = b"infected"
TASK_IDS = [101, 102, 103]
REPORTS: dict[int, dict] = {}


def _when(minutes_ago: int) -> str:
    when = datetime.now(UTC) - timedelta(minutes=minutes_ago)
    return when.strftime("%Y-%m-%d %H:%M:%S")


def _yara(count: int = 1) -> list[dict]:
    return [
        {
            "name": fake.word().capitalize(),
            "strings": [],
            "meta": {
                "description": fake.sentence(),
                "author": "kevoreilly",
                "cape_type": "Emotet Payload",
            },
            "addresses": {},
        }
        for _ in range(count)
    ]


def _file(name: str) -> dict:
    return {
        "name": name,
        "path": f"/opt/CAPEv2/storage/binaries/{name}",
        "type": "PE32 executable (GUI) Intel 80386, for MS Windows",
        "size": fake.random_int(20000, 900000),
        "crc32": "A1B2C3D4",
        "md5": fake.md5(),
        "sha1": fake.sha1(),
        "sha256": fake.sha256(),
        "sha512": fake.sha256() + fake.sha256(),
        "ssdeep": "3072:" + fake.pystr(20, 20) + ":" + fake.pystr(20, 20),
        "tlsh": "T1" + fake.pystr(68, 68).upper(),
        "sha3_384": fake.sha256() + fake.sha256()[:32],
        "yara": _yara(),
        "cape_yara": _yara(),
        "clamav": [f"Win.Trojan.{fake.word().capitalize()}-1"],
        "trid": ["42.0% (.EXE) Win32 Executable (generic)", "31.4% (.DLL) Win32 DLL"],
    }


def _payload(name: str) -> dict:
    return {
        **_file(name),
        "module_path": f"C:\\Users\\admin\\AppData\\Local\\Temp\\{name}",
        "cape_type": "Emotet Payload",
        "flare_capa": {"ATTCK": {"Defense Evasion": ["T1055"], "Execution": ["T1059"]}},
    }


def _process(pid: int, parent: int, command: str, children: list[dict]) -> dict:
    return {
        "pid": pid,
        "parent_id": parent,
        "name": command.split("\\")[-1],
        "module_path": command,
        "environ": {"CommandLine": command, "UserName": "admin"},
        "threads": [],
        "children": children,
    }


def report(task_id: int) -> dict:
    """The report of a task, made once so that its archives match its hashes."""
    if task_id not in REPORTS:
        REPORTS[task_id] = _report(task_id)
    return REPORTS[task_id]


def _report(task_id: int) -> dict:
    """A CAPE JSON report of a malicious executable with the sections connectors map."""
    family = FAMILIES[task_id % len(FAMILIES)]
    target = _file(f"sample-{task_id}.exe")
    dropper = r"C:\Users\admin\AppData\Local\Temp\dropper.exe"
    return {
        "info": {
            "id": task_id,
            "started": _when(30),
            "ended": _when(25),
            "duration": 300,
            "category": "file",
            "route": "none",
            "package": "exe",
            "machine": {
                "label": "win10-1",
                "manager": "KVM",
                "name": "win10-1",
                "shutdown_on": _when(25),
                "started_on": _when(30),
                "status": "stopped",
            },
            "version": "2.4-CAPE",
            "tlp": "GREEN",
        },
        "malscore": 8.5,
        "detections": [{"family": family, "details": [{"Emotet": "yara"}]}],
        "target": {"category": "file", "file": target},
        "trid": target["trid"],
        "signatures": [
            {
                "description": fake.sentence(),
                "weight": 3,
                "name": "injection_createremotethread",
                "confidence": 80,
                "references": [],
                "data": [],
                "new_data": [],
                "alert": False,
                "severity": 3,
                "families": [family],
            }
        ],
        "ttps": [
            {"ttp": "T1055", "signature": "injection_createremotethread"},
            {"ttp": "T1059", "signature": "command_line_execution"},
        ],
        "network": {
            "dead_hosts": [],
            "domains": [
                {"domain": fake.domain_name(), "ip": fake.ipv4_public()}
                for _ in range(2)
            ],
            "hosts": [
                {
                    "ip": fake.ipv4_public(),
                    "country_name": "France",
                    "hostname": "",
                    "inaddrarpa": "",
                }
                for _ in range(2)
            ],
            "dns": [],
            "http": [],
            "http_ex": [],
            "icmp": [
                {
                    "data": "",
                    "dst": fake.ipv4_public(),
                    "src": "192.168.122.101",
                    "type": 8,
                }
            ],
            "tcp": [
                {
                    "dport": 443,
                    "dst": fake.ipv4_public(),
                    "offset": 1024,
                    "sport": 49200,
                    "src": "192.168.122.101",
                    "time": 4.2,
                }
            ],
            "udp": [
                {
                    "dport": 53,
                    "dst": "8.8.8.8",
                    "offset": 512,
                    "sport": 52000,
                    "src": "192.168.122.101",
                    "time": 1.1,
                }
            ],
        },
        "behavior": {
            "processtree": [
                _process(
                    2104,
                    1800,
                    r"C:\Users\admin\Desktop\sample.exe",
                    [_process(2210, 2104, dropper, [])],
                )
            ],
            "summary": {
                "files": [dropper],
                "write_files": [dropper],
                "keys": [],
                "write_keys": [
                    r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\x"
                ],
                "executed_commands": [dropper],
                "resolved_apis": ["kernel32.dll.CreateProcessW"],
                "mutexes": ["Global\\M" + fake.pystr(8, 8)],
            },
        },
        "CAPE": {
            "payloads": [_payload(f"payload-{task_id}.bin")],
            "configs": [
                {
                    family: {
                        "address": [
                            f"{fake.ipv4_public()}:8080",
                            f"https://{fake.domain_name()}:443/gate.php",
                        ]
                    }
                }
            ],
        },
        "procdump": [_payload(f"procdump-{task_id}.bin")],
        "strings": [],
    }


def _task(task_id: int) -> dict:
    return {
        "id": task_id,
        "category": "file",
        "target": f"/opt/CAPEv2/storage/binaries/sample-{task_id}.exe",
        "status": "reported",
        "added_on": _when(40),
        "started_on": _when(30),
        "completed_on": _when(25),
    }


def _zip_crypto(name: str, data: bytes) -> bytes:
    """A zip archive of one file encrypted with the traditional zip password."""
    table = []
    for i in range(256):
        value = i
        for _ in range(8):
            value = (value >> 1) ^ 0xEDB88320 if value & 1 else value >> 1
        table.append(value)
    keys = [0x12345678, 0x23456789, 0x34567890]

    def update(byte: int) -> None:
        keys[0] = (keys[0] >> 8) ^ table[(keys[0] ^ byte) & 0xFF]
        keys[1] = ((keys[1] + (keys[0] & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
        keys[2] = (keys[2] >> 8) ^ table[(keys[2] ^ (keys[1] >> 24)) & 0xFF]

    def encrypt(plain: bytes) -> bytes:
        out = bytearray()
        for byte in plain:
            stream = (keys[2] | 2) & 0xFFFF
            out.append(byte ^ ((stream * (stream ^ 1)) >> 8) & 0xFF)
            update(byte)
        return bytes(out)

    for byte in ZIP_PASSWORD:
        update(byte)
    crc = zlib.crc32(data)
    header = bytes(range(11)) + bytes([crc >> 24])
    body = encrypt(header + data)
    filename = name.encode()
    stamp = struct.pack("<HH", 0, 0x21)
    local = struct.pack(
        "<IHHH4sIIIHH",
        0x04034B50, 20, 1, 0, stamp, crc, len(body), len(data), len(filename), 0,
    )  # fmt: skip
    central = struct.pack(
        "<IHHHH4sIIIHHHHHII",
        0x02014B50, 20, 20, 1, 0, stamp, crc, len(body), len(data),
        len(filename), 0, 0, 0, 0, 0, 0,
    )  # fmt: skip
    offset = len(local) + len(filename) + len(body)
    directory = central + filename
    end = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, 1, 1, len(directory), offset, 0)
    return local + filename + body + directory + end


@router.get("/apiv2/tasks/list")
@router.get("/apiv2/tasks/list/")
async def tasks_list() -> dict:
    """Finished tasks, the newest first."""
    return {"error": False, "data": [_task(i) for i in reversed(TASK_IDS)]}


@router.get("/apiv2/tasks/get/report/{task_id}")
@router.get("/apiv2/tasks/get/report/{task_id}/")
async def task_report(task_id: int) -> dict:
    return report(task_id)


@router.get("/apiv2/tasks/status/{task_id}/")
async def task_status() -> dict:
    return {"error": False, "data": "reported"}


@router.post("/apiv2/tasks/create/file/")
async def task_create() -> dict:
    """A submitted sample becomes the first task."""
    return {
        "error": False,
        "data": {"task_ids": [TASK_IDS[0]], "message": f"Task IDs [{TASK_IDS[0]}]"},
    }


@router.get("/apiv2/tasks/get/procdumpfiles/{task_id}/")
async def procdump_files(task_id: int) -> Response:
    """The process dumps, as a zip named by the SHA-256 of each dump."""
    sha256 = report(task_id)["procdump"][0]["sha256"]
    return Response(
        _zip_crypto(sha256, b"MZ" + bytes(range(64))), media_type="application/zip"
    )


@router.get("/apiv2/tasks/get/payloadfiles/{task_id}/")
async def payload_files(task_id: int) -> Response:
    sha256 = report(task_id)["CAPE"]["payloads"][0]["sha256"]
    return Response(
        _zip_crypto(f"CAPE/{sha256}", b"MZ" + bytes(range(64))),
        media_type="application/zip",
    )


@router.get("/apiv2/{path:path}", include_in_schema=False)
async def unknown(path: str) -> JSONResponse:
    return JSONResponse({"error": True, "error_value": f"unknown {path}"}, 404)
