"""Factories for the AWS IAM Roles Anywhere ``CreateSession`` API.

See https://docs.aws.amazon.com/rolesanywhere/latest/userguide/authentication.html
"""

import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta

import factory


@dataclass
class RolesAnywhereCredentials:
    accessKeyId: str  # noqa: N815
    secretAccessKey: str  # noqa: N815
    sessionToken: str  # noqa: N815
    expiration: str


@dataclass
class RolesAnywhereCredentialSetEntry:
    credentials: RolesAnywhereCredentials
    roleArn: str  # noqa: N815
    packedPolicySize: int  # noqa: N815
    sourceIdentity: str  # noqa: N815
    assumedRoleUser: dict = field(default_factory=dict)


class RolesAnywhereCredentialsFactory(factory.Factory):
    class Meta:
        model = RolesAnywhereCredentials

    accessKeyId = factory.LazyFunction(lambda: "ASIA" + uuid.uuid4().hex[:16].upper())
    secretAccessKey = factory.LazyFunction(lambda: uuid.uuid4().hex + uuid.uuid4().hex)
    sessionToken = factory.LazyFunction(lambda: "FAKE." + uuid.uuid4().hex * 4)
    expiration = factory.LazyFunction(
        lambda: (datetime.now(UTC) + timedelta(hours=1)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
    )


def build_create_session_response(role_arn: str, profile_arn: str) -> dict:
    """Build a fake ``CreateSession`` response for the given role/profile ARNs."""
    entry = RolesAnywhereCredentialSetEntry(
        credentials=RolesAnywhereCredentialsFactory(),
        roleArn=role_arn,
        packedPolicySize=0,
        sourceIdentity="",
        assumedRoleUser={
            "arn": role_arn,
            "assumedRoleId": uuid.uuid4().hex[:21].upper(),
        },
    )
    return {"credentialSet": [asdict(entry)], "subjectArn": profile_arn}
