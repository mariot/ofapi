import gzip
import io
import json
from typing import Annotated

from fastapi import FastAPI, Query
from fastapi.responses import StreamingResponse
from api.hunt_io import C2FeedFactory

app = FastAPI()


@app.get("/hunt-io/feeds/c2", tags=["Hunt-IO"], response_class=StreamingResponse)
async def hunt_io_feeds_c2():
    """Hunt-IO C2 Feed Endpoint

    Returns a gzipped stream of C2 feed data in JSON Lines format."""
    c2_feed_batch = C2FeedFactory.create_batch(10)
    json_data = "\n".join([json.dumps(item.to_dict()) for item in c2_feed_batch])
    encoded = json_data.encode("utf-8")
    gzip_buffer = io.BytesIO(gzip.compress(encoded))
    return StreamingResponse(
        gzip_buffer,
        media_type="application/gzip",
        headers={"Content-Type": "application/gzip"},
    )


@app.get("/feedly/v3/enterprise/ioc", tags=["Feedly"])
async def feedly_enterprise_ioc(
        stream_id: Annotated[str, Query(alias="streamId")],
        newer_than: Annotated[str, Query(alias="newerThan")],
        count: int = Query(10, alias="count"),
        continuation: int = Query(0, alias="continuation"),
):
    """Feedly Enterprise IOC Endpoint

    Returns a sample response for Feedly Enterprise IOC."""
    sample_response = {
        "objects": [
            {
                "type": "report",
                "spec_version": "2.1",
                "id": "grouping--e10219e8-edf9-46f5-ab1a-2dc84f74ac8b",
                "created": "2022-02-11T08:08:01.131733Z",
                "modified": "2022-02-11T08:08:01.131733Z",
                "published": "2022-02-11T08:08:01.131733Z",
                "name": "Threat actor groups are targeting VMware Horizon servers running versions affected by Log4Shell vulnerabilities…",
                "description": "• Post exploitation, the threat actors use encoded PowerShell commands to download a second-stage payload (such as Cobalt Strike beacons, Crypto miner or ransomware) to the victim systems. Use the PowerShell command to detect malicious file modification activity.",
                "context": "unspecified",
                "object_refs": [
                    "malware--1a1d3ea4-972e-4c48-8d85-08d9db8f1550",
                    "attack-pattern--7385dfaf-6886-4229-9ecd-6fd678040830",
                    "domain-name--cb403063-a319-5b81-8160-b3f04cb6b9a9",
                    "url--a97b9642-9c68-5bc0-97a4-6488a7a06d58",
                    "ipv4-addr--34fc35a8-b548-5083-ace8-6d65bcfce5d7",
                ],
                "external_references": [
                    {
                        "source_name": "Feedly article",
                        "url": "https://feedly.com/i/entry/lpNdEKDz4G+795+TnrSpAd6SUK5+88ulJrCUUbPk/6I=_17ee7d2facc:14ddcbb:aa31659c"
                    },
                    {
                        "source_name": "Checkmate",
                        "url": "https://niiconsulting.com/checkmate/2022/02/threat-actor-groups-are-targeting-vmware-horizon-servers-running-versions-affected-by-log4shell-vulnerabilities/"
                    }
                ]
            },
            {
                "type": "malware",
                "spec_version": "2.1",
                "id": "malware--1a1d3ea4-972e-4c48-8d85-08d9db8f1550",
                "created": "2022-02-10T20:30:40.279281Z",
                "modified": "2022-02-10T20:30:40.279281Z",
                "name": "Cobalt Strike",
                "description": "Cobalt Strike is a paid penetration testing product that allows an attacker to deploy an agent named 'Beacon' on the victim machine. Beacon includes a wealth of functionality to the attacker, including, but not limited to command execution, key logging, file transfer, SOCKS proxying, privilege escalation, mimikatz, port scanning and lateral movement. Beacon is in-memory/file-less, in that it consists of stageless or multi-stage shellcode that once loaded by exploiting a vulnerability or executing a shellcode loader, will reflectively load itself into the memory of a process without touching the disk. It supports C2 and staging over HTTP, HTTPS, DNS, SMB named pipes as well as forward and reverse TCP; Beacons can be daisy-chained. Cobalt Strike comes with a toolkit for developing shellcode loaders, called Artifact Kit.\r\n\r\nThe Beacon implant has become popular amongst targeted attackers and criminal users as it is well written, stable, and highly customizable.",
                "is_family": True,
                "aliases": [
                    "Agentemis",
                    "BEACON",
                    "CobaltStrike"
                ],
                "external_references": [
                    {
                        "source_name": "",
                        "url": "http://blog.morphisec.com/new-global-attack-on-point-of-sale-systems"
                    },
                ]
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--2e34237d-8574-43f6-aace-ae2915de8597",
                "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
                "created": "2020-03-02T19:05:18.137Z",
                "modified": "2021-04-01T16:21:17.553Z",
                "name": "Spearphishing Attachment",
                "description": "Adversaries may send spearphishing emails with a malicious attachment in an attempt to gain access to victim systems. Spearphishing attachment is a specific variant of spearphishing. Spearphishing attachment is different from other forms of spearphishing in that it employs the use of malware attached to an email. All forms of spearphishing are electronically delivered social engineering targeted at a specific individual, company, or industry. In this scenario, adversaries attach a file to the spearphishing email and usually rely upon [User Execution](https://attack.mitre.org/techniques/T1204) to gain execution. Spearphishing may also involve social engineering techniques, such as posing as a trusted source.\n\nThere are many options for the attachment such as Microsoft Office documents, executables, PDFs, or archived files. Upon opening the attachment (and potentially clicking past protections), the adversary's payload exploits a vulnerability or directly executes on the user's system. The text of the spearphishing email usually tries to give a plausible reason why the file should be opened, and may explain how to bypass system protections in order to do so. The email may also contain instructions on how to decrypt an attachment, such as a zip file password, in order to evade email boundary defenses. Adversaries frequently manipulate file extensions and icons in order to make attached executables appear to be document files, or files exploiting one application appear to be a file for a different one. ",
                "kill_chain_phases": [
                    {
                        "kill_chain_name": "mitre-attack",
                        "phase_name": "initial-access"
                    }
                ],
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "url": "https://attack.mitre.org/techniques/T1566/001",
                        "external_id": "T1566.001"
                    },
                ],
                "object_marking_refs": [
                    "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"
                ],
                "x_mitre_contributors": [
                    "Philip Winther"
                ],
                "x_mitre_data_sources": [
                    "Application Log: Application Log Content",
                    "Network Traffic: Network Traffic Content",
                    "Network Traffic: Network Traffic Flow"
                ],
                "x_mitre_detection": "Network intrusion detection systems and email gateways can be used to detect spearphishing with malicious attachments in transit. Detonation chambers may also be used to identify malicious attachments. Solutions can be signature and behavior based, but adversaries may construct attachments in a way to avoid these systems.\n\nFiltering based on DKIM+SPF or header analysis can help detect when the email sender is spoofed.(Citation: Microsoft Anti Spoofing)(Citation: ACSC Email Spoofing)\n\nAnti-virus can potentially detect malicious documents and attachments as they're scanned to be stored on the email server or on the user's computer. Endpoint sensing or network sensing can potentially detect malicious events once the attachment is opened (such as a Microsoft Word document or PDF reaching out to the internet or spawning Powershell.exe) for techniques such as [Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203) or usage of malicious scripts.\n\nMonitor for suspicious descendant process spawning from Microsoft Office and other productivity software.(Citation: Elastic - Koadiac Detection with EQL)",
                "x_mitre_is_subtechnique": True,
                "x_mitre_platforms": [
                    "macOS",
                    "Windows",
                    "Linux"
                ],
                "x_mitre_version": "2.1"
            },
            {
                "type": "domain-name",
                "spec_version": "2.1",
                "id": "domain-name--cb403063-a319-5b81-8160-b3f04cb6b9a9",
                "value": "b.oracleservice.top"
            },
            {
                "type": "url",
                "spec_version": "2.1",
                "id": "url--2c87a8fc-9c0b-56e4-ba7f-96f09ab8cb77",
                "value": "http://149.28.200.140:443/winntaa.exe"
            },
            {
                "type": "ipv4-addr",
                "spec_version": "2.1",
                "id": "ipv4-addr--34fc35a8-b548-5083-ace8-6d65bcfce5d7",
                "value": "140.246.171.141"
            },
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": "indicator--3a715b14-5d82-499f-b0a2-86b7444745da",
                "created": "2022-02-10T14:00:29.171064Z",
                "modified": "2022-02-10T14:00:29.171064Z",
                "name": "Hash",
                "pattern": "[file:hashes.MD5 = '29bc15a6f0ff99084e986c3e6ab1208c']",
                "pattern_type": "stix",
                "pattern_version": "2.1",
                "valid_from": "2022-02-10T14:00:29.171064Z"
            },
        ],
        "id": "bundle--2cd2674c-f6e1-49b0-a714-6d5f2dc87ceb",
        "type": "bundle"
    }
    return sample_response
