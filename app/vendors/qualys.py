"""Qualys legacy XML APIs: the KnowledgeBase and the host detections (qualys-cve-enrichment)."""

# ruff: noqa: E501  (XML payloads)

from fastapi import APIRouter, Form, Response

from app.fake import fake

HOSTS = ["qualysapi.qualys.com"]
router = APIRouter(prefix="/qualys", tags=["Qualys"])


def _xml(body: str) -> Response:
    return Response(content=body, media_type="text/xml;charset=UTF-8")


def _when() -> str:
    return fake.date_time_this_year().strftime("%Y-%m-%dT%H:%M:%SZ")


@router.post("/api/3.0/fo/knowledge_base/vuln/")
async def knowledge_base(cve: str = Form("")) -> Response:
    """The vulnerability of the Qualys KnowledgeBase carrying the CVE."""
    qid = fake.random_int(100000, 999999)
    vendor = fake.company()
    return _xml(f"""<?xml version="1.0" encoding="UTF-8" ?>
<KNOWLEDGE_BASE_VULN_LIST_OUTPUT>
<RESPONSE>
<DATETIME>{_when()}</DATETIME>
<VULN_LIST>
<VULN>
<QID>{qid}</QID>
<VULN_TYPE>Vulnerability</VULN_TYPE>
<SEVERITY_LEVEL>4</SEVERITY_LEVEL>
<TITLE><![CDATA[{vendor} Remote Code Execution Vulnerability]]></TITLE>
<CATEGORY>Local</CATEGORY>
<LAST_SERVICE_MODIFICATION_DATETIME>{_when()}</LAST_SERVICE_MODIFICATION_DATETIME>
<PUBLISHED_DATETIME>{_when()}</PUBLISHED_DATETIME>
<BUGTRAQ_LIST>
<BUGTRAQ><ID><![CDATA[{fake.random_int(10000, 99999)}]]></ID><URL><![CDATA[http://www.securityfocus.com/bid/{fake.random_int(10000, 99999)}]]></URL></BUGTRAQ>
</BUGTRAQ_LIST>
<PATCHABLE>1</PATCHABLE>
<SOFTWARE_LIST>
<SOFTWARE><PRODUCT><![CDATA[{fake.word().capitalize()} Server]]></PRODUCT><VENDOR><![CDATA[{vendor}]]></VENDOR></SOFTWARE>
<SOFTWARE><PRODUCT><![CDATA[{fake.word().capitalize()} Client]]></PRODUCT><VENDOR><![CDATA[{vendor}]]></VENDOR></SOFTWARE>
</SOFTWARE_LIST>
<VENDOR_REFERENCE_LIST>
<VENDOR_REFERENCE><ID><![CDATA[{vendor} advisory]]></ID><URL><![CDATA[{fake.url()}]]></URL></VENDOR_REFERENCE>
</VENDOR_REFERENCE_LIST>
<CVE_LIST>
<CVE><ID><![CDATA[{cve.upper()}]]></ID><URL><![CDATA[http://cve.mitre.org/cgi-bin/cvename.cgi?name={cve.upper()}]]></URL></CVE>
</CVE_LIST>
<DIAGNOSIS><![CDATA[A remote attacker can run arbitrary code.<P>See <A HREF="{fake.url()}" TARGET="_blank">the advisory</A> for <B>details</B>.]]></DIAGNOSIS>
<CONSEQUENCE><![CDATA[Successful exploitation allows an attacker to take control of the host.]]></CONSEQUENCE>
<SOLUTION><![CDATA[Install the vendor patch.<UL><LI>Update the product</LI><LI>Restart the service</LI></UL>]]></SOLUTION>
<CORRELATION>
<EXPLOITS>
<EXPLT_SRC>
<SRC_NAME><![CDATA[The Exploit-DB]]></SRC_NAME>
<EXPLT_LIST>
<EXPLT><REF><![CDATA[CVE-2017-0144]]></REF><DESC><![CDATA[Remote exploit]]></DESC><LINK><![CDATA[{fake.url()}]]></LINK></EXPLT>
</EXPLT_LIST>
</EXPLT_SRC>
</EXPLOITS>
<MALWARE>
<MW_SRC>
<SRC_NAME><![CDATA[Trend Micro]]></SRC_NAME>
<MW_LIST><MW_INFO><MW_ID><![CDATA[{fake.malware_family()}]]></MW_ID><MW_TYPE><![CDATA[Trojan]]></MW_TYPE><MW_PLATFORM><![CDATA[Windows]]></MW_PLATFORM><MW_ALIAS><![CDATA[none]]></MW_ALIAS><MW_RATING><![CDATA[High]]></MW_RATING><MW_LINK><![CDATA[{fake.url()}]]></MW_LINK></MW_INFO></MW_LIST>
</MW_SRC>
</MALWARE>
</CORRELATION>
<CVSS>
<BASE source="service">9.3</BASE>
<TEMPORAL>7.7</TEMPORAL>
<ACCESS><VECTOR>Network</VECTOR><COMPLEXITY>Medium</COMPLEXITY></ACCESS>
<AUTHENTICATION>None</AUTHENTICATION>
</CVSS>
<CVSS_V3>
<BASE>8.8</BASE>
<TEMPORAL>8.2</TEMPORAL>
<ATTACK><VECTOR>Network</VECTOR><COMPLEXITY>Low</COMPLEXITY></ATTACK>
<PRIVILEGES_REQUIRED>None</PRIVILEGES_REQUIRED>
<USER_INTERACTION>Required</USER_INTERACTION>
<SCOPE>Unchanged</SCOPE>
</CVSS_V3>
<DISCOVERY><REMOTE>1</REMOTE></DISCOVERY>
<QDS severity="HIGH">{fake.random_int(70, 95)}</QDS>
<QDS_FACTORS>
<QDS_FACTOR name="CVSS">9.3</QDS_FACTOR>
<QDS_FACTOR name="RTI">Exploit_Public, Remote_Code_Execution</QDS_FACTOR>
<QDS_FACTOR name="Exploit Maturity">weaponized</QDS_FACTOR>
</QDS_FACTORS>
</VULN>
</VULN_LIST>
</RESPONSE>
</KNOWLEDGE_BASE_VULN_LIST_OUTPUT>
""")


@router.post("/api/3.0/fo/asset/host/vm/detection/")
async def host_detections(qids: str = Form("")) -> Response:
    """The hosts the QID was detected on."""
    hosts = "".join(
        f"""<HOST>
<ID>{fake.random_int(10000, 99999)}</ID>
<IP>{fake.ipv4_private()}</IP>
<TRACKING_METHOD>IP</TRACKING_METHOD>
<OS><![CDATA[Windows Server 2019 Standard]]></OS>
<DNS><![CDATA[{fake.hostname()}]]></DNS>
<LAST_SCAN_DATETIME>{_when()}</LAST_SCAN_DATETIME>
<DETECTION_LIST>
<DETECTION>
<QID>{qids.split(",")[0]}</QID>
<TYPE>Confirmed</TYPE>
<SEVERITY>4</SEVERITY>
<STATUS>Active</STATUS>
<FIRST_FOUND_DATETIME>{_when()}</FIRST_FOUND_DATETIME>
<LAST_FOUND_DATETIME>{_when()}</LAST_FOUND_DATETIME>
<TIMES_FOUND>{fake.random_int(1, 30)}</TIMES_FOUND>
</DETECTION>
</DETECTION_LIST>
</HOST>"""
        for _ in range(3)
    )
    return _xml(f"""<?xml version="1.0" encoding="UTF-8" ?>
<HOST_LIST_VM_DETECTION_OUTPUT>
<RESPONSE>
<DATETIME>{_when()}</DATETIME>
<HOST_LIST>
{hosts}
</HOST_LIST>
</RESPONSE>
</HOST_LIST_VM_DETECTION_OUTPUT>
""")
