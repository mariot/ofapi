"""Factories for the Slack Web API (``slack.com/api``).

Slack always answers HTTP 200 and signals logical failures through the ``ok``
field, so the fake API mirrors the successful ``chat.postMessage`` envelope.
"""

from dataclasses import dataclass

import factory


@dataclass
class PostedMessage:
    type: str
    subtype: str
    text: str
    user: str
    ts: str
    bot_id: str
    app_id: str
    team: str


class PostedMessageFactory(factory.Factory):
    class Meta:
        model = PostedMessage

    type = "message"
    subtype = "bot_message"
    text = factory.Faker("sentence", nb_words=8)
    user = factory.Faker("bothify", text="U########?")
    ts = factory.Faker("numerify", text="##########.######")
    bot_id = factory.Faker("bothify", text="B########?")
    app_id = factory.Faker("bothify", text="A########?")
    team = factory.Faker("bothify", text="T########?")
