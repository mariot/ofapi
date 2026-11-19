"""AWS EC2 Query API (DescribeInstances), reached by boto3 via AWS_ENDPOINT_URL_EC2.

The EC2 Query protocol answers XML. Three instances exercise the aws-resources
collector's filters: a running one with private and public IPs, a terminated one
(skipped) and a stopped one without any address (skipped).
"""

from xml.sax.saxutils import escape

EC2_NAMESPACE = "http://ec2.amazonaws.com/doc/2016-11-15/"

INSTANCES = [
    {
        "id": "i-0ofapi000000000001",
        "name": "ofapi-web-1",
        "state": ("16", "running"),
        "private_ip": "10.0.1.10",
        "public_ip": "198.51.100.10",
        "platform_details": "Linux/UNIX",
        "architecture": "x86_64",
    },
    {
        "id": "i-0ofapi000000000002",
        "name": "ofapi-terminated",
        "state": ("48", "terminated"),
        "private_ip": "10.0.1.11",
        "public_ip": None,
        "platform_details": "Linux/UNIX",
        "architecture": "x86_64",
    },
    {
        "id": "i-0ofapi000000000003",
        "name": "ofapi-no-ip",
        "state": ("80", "stopped"),
        "private_ip": None,
        "public_ip": None,
        "platform_details": "Windows",
        "architecture": "x86_64",
    },
]


def _instance_xml(instance: dict, region: str) -> str:
    code, state = instance["state"]
    parts = [
        f"<instanceId>{instance['id']}</instanceId>",
        "<imageId>ami-0ofapi00000000001</imageId>",
        f"<instanceState><code>{code}</code><name>{state}</name></instanceState>",
        "<instanceType>t3.micro</instanceType>",
        f"<placement><availabilityZone>{region}a</availabilityZone></placement>",
        f"<platformDetails>{instance['platform_details']}</platformDetails>",
        f"<architecture>{instance['architecture']}</architecture>",
        f"<tagSet><item><key>Name</key><value>{escape(instance['name'])}</value></item>"
        "<item><key>env</key><value>ofapi</value></item></tagSet>",
    ]
    if instance["private_ip"]:
        parts.append(f"<privateIpAddress>{instance['private_ip']}</privateIpAddress>")
    if instance["public_ip"]:
        parts.append(f"<ipAddress>{instance['public_ip']}</ipAddress>")
    return "<item>" + "".join(parts) + "</item>"


def describe_instances_xml(region: str = "us-east-1") -> str:
    instances = "".join(_instance_xml(i, region) for i in INSTANCES)
    return (
        f'<?xml version="1.0" encoding="UTF-8"?>'
        f'<DescribeInstancesResponse xmlns="{EC2_NAMESPACE}">'
        "<requestId>ofapi-request-1</requestId>"
        "<reservationSet><item><reservationId>r-0ofapi0000000001</reservationId>"
        "<ownerId>123456789012</ownerId><groupSet/>"
        f"<instancesSet>{instances}</instancesSet>"
        "</item></reservationSet></DescribeInstancesResponse>"
    )


def error_xml(code: str, message: str) -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8"?><Response><Errors><Error>'
        f"<Code>{escape(code)}</Code><Message>{escape(message)}</Message>"
        "</Error></Errors><RequestID>ofapi-request-1</RequestID></Response>"
    )
