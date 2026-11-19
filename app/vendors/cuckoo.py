"""Cuckoo Sandbox 2.x REST API: the task list and the task summary (report), read by
the OpenCTI cuckoo connector. The instance is a made-up host (no vendor URL exists)."""

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, HTTPException

from app.fake import fake

HOSTS = ["cuckoo.staticfire.test"]
router = APIRouter(prefix="/cuckoo", tags=["Cuckoo"])

TASK_IDS = [101, 102, 103]


def _stamp(minutes_ago: int) -> str:
    moment = datetime.now(UTC) - timedelta(minutes=minutes_ago)
    return moment.strftime("%Y-%m-%d %H:%M:%S")


def _hashes() -> dict:
    return {
        "crc32": fake.md5()[:8].upper(),
        "md5": fake.md5(),
        "sha1": fake.sha1(),
        "sha256": fake.sha256(),
        "sha512": fake.sha256() + fake.sha256(),
        "ssdeep": fake.ssdeep(),
    }


def _file(name: str, kind: str, **extra) -> dict:
    return {
        "name": name,
        "path": f"/cuckoo/storage/{name}",
        **_hashes(),
        "size": fake.random_int(2000, 900000),
        "type": kind,
        "yara": [],
        "urls": [],
        **extra,
    }


def _process(pid: int, ppid: int, name: str, children: list[dict]) -> dict:
    return {
        "pid": pid,
        "ppid": ppid,
        "process_name": name,
        "command_line": f"C:\\Users\\victim\\{name}",
        "first_seen": datetime.now(UTC).timestamp(),
        "track": True,
        "children": children,
    }


def _report(task_id: int) -> dict:
    sample = fake.file_name(extension="exe")
    c2_domain, c2_ip = fake.domain_name(), fake.ipv4_public()
    started = _stamp(30)
    return {
        "info": {
            "id": task_id,
            "added": started,
            "started": started,
            "ended": _stamp(20),
            "duration": 600,
            "category": "file",
            "route": "internet",
            "package": "exe",
            "score": fake.random_int(7, 10),
            "platform": "windows",
            "version": "2.0.7",
            "machine": {
                "label": "win7x64",
                "manager": "VirtualBox",
                "name": "win7x64",
                "shutdown_on": _stamp(19),
                "started_on": started,
                "status": "stopped",
            },
        },
        "target": {
            "category": "file",
            "file": _file(sample, "PE32 executable (GUI) Intel 80386, for MS Windows"),
        },
        "network": {
            "id": task_id,
            "dead_hosts": [],
            "dns_servers": ["8.8.8.8"],
            "domains": [{"domain": c2_domain, "ip": c2_ip}],
            "hosts": [c2_ip, fake.ipv4_public()],
            "dns": [
                {
                    "request": c2_domain,
                    "type": "A",
                    "answers": [{"data": c2_ip, "type": "A"}],
                }
            ],
            "http": [
                {
                    "host": c2_domain,
                    "port": 80,
                    "method": "GET",
                    "path": "/gate.php",
                    "uri": f"http://{c2_domain}/gate.php",
                    "user-agent": "Mozilla/4.0",
                    "version": "1.1",
                    "body": "",
                    "data": "",
                    "count": 1,
                }
            ],
            "http_ex": [],
            "icmp": [],
            "tcp": [
                {
                    "dport": 443,
                    "dst": c2_ip,
                    "offset": 1024,
                    "sport": 49161,
                    "src": "192.168.56.101",
                    "time": 4.2,
                }
            ],
            "udp": [
                {
                    "dport": 53,
                    "dst": "8.8.8.8",
                    "offset": 512,
                    "sport": 52000,
                    "src": "192.168.56.101",
                    "time": 1.1,
                }
            ],
        },
        "behavior": {
            "processtree": [
                _process(
                    1200,
                    700,
                    sample,
                    [
                        _process(
                            1300, 1200, "cmd.exe", [_process(1400, 1300, "net.exe", [])]
                        )
                    ],
                )
            ],
            "summary": {
                "command_line": [f"C:\\Users\\victim\\{sample}"],
                "mutex": ["Global\\" + fake.md5()[:12]],
                "regkey_written": [
                    "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\"
                    + fake.word()
                ],
                "file_created": ["C:\\Users\\victim\\AppData\\Roaming\\update.exe"],
                "resolves_host": [c2_domain],
                "connects_ip": [c2_ip],
            },
        },
        "signatures": [
            {
                "name": "persistence_autorun",
                "description": "Installs itself for autorun at Windows startup",
                "severity": 3,
                "markcount": 1,
                "families": [],
                "references": [],
                "ttp": {
                    "T1060": {
                        "short": "Registry Run Keys",
                        "long": "Run keys persist.",
                    },
                    "T1112": {"short": "Modify Registry", "long": "Registry edited."},
                },
            },
            {
                "name": "antivm_checks_available_memory",
                "description": "Checks amount of memory in system",
                "severity": 1,
                "markcount": 2,
                "families": [],
                "references": [],
                "ttp": {},
            },
        ],
        "extracted": [
            {
                "category": "script",
                "pid": 1200,
                "info": {},
                "program": "powershell",
                "raw": "C:\\Users\\victim\\payload.ps1",
                "yara": [],
                "first_seen": datetime.now(UTC).timestamp(),
            }
        ],
        "dropped": [
            _file(
                "update.exe",
                "PE32 executable (GUI) Intel 80386, for MS Windows",
                filepath="C:\\Users\\victim\\AppData\\Roaming\\update.exe",
                pids=[1200],
            ),
            _file(
                "run.bat",
                "DOS batch file, ASCII text script",
                filepath="C:\\Users\\victim\\run.bat",
                pids=[1300],
            ),
        ],
        "buffer": [],
        "strings": [],
    }


@router.get("/api/tasks/list")
async def tasks_list() -> dict:
    """Reported tasks, plus one still running that the connector must skip."""
    tasks = [
        {
            "id": task_id,
            "status": "reported",
            "category": "file",
            "completed_on": _stamp(20),
            "added_on": _stamp(40),
            "target": fake.file_name(extension="exe"),
        }
        for task_id in TASK_IDS
    ]
    tasks.append(
        {
            "id": TASK_IDS[-1] + 1,
            "status": "running",
            "category": "file",
            "completed_on": None,
            "added_on": _stamp(5),
        }
    )
    return {"tasks": tasks}


@router.get("/api/tasks/summary/{task_id}")
async def task_summary(task_id: int) -> dict:
    if task_id not in TASK_IDS:
        raise HTTPException(404, "Task not found")
    return _report(task_id)
