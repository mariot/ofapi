"""Factories for Google OAuth2 and the Gmail API.

The OpenAEV ``email-google-workspace`` injector authenticates with a service
account (google-auth signs a JWT and exchanges it at the ``token_uri`` declared in
the service account JSON) and then calls
``POST /users/me/messages/send``. Pointing ``token_uri`` at the fake token
endpoint is enough to run the whole flow offline.
"""

from dataclasses import dataclass, field

import factory


@dataclass
class GoogleToken:
    access_token: str
    expires_in: int
    token_type: str
    scope: str


@dataclass
class GmailMessage:
    id: str
    threadId: str  # noqa: N815 - Gmail uses camelCase on the wire
    labelIds: list[str] = field(default_factory=list)  # noqa: N815


class GoogleTokenFactory(factory.Factory):
    class Meta:
        model = GoogleToken

    access_token = factory.Faker("bothify", text="ya29.?????????????????????????")
    expires_in = 3599
    token_type = "Bearer"
    scope = "https://www.googleapis.com/auth/gmail.send"


class GmailMessageFactory(factory.Factory):
    class Meta:
        model = GmailMessage

    id = factory.Faker("bothify", text="1???????????????")
    threadId = factory.Faker("bothify", text="1???????????????")
    labelIds = factory.List(["SENT"])
