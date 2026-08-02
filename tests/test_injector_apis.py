"""Tests for the fake APIs backing the OpenAEV injectors."""

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)

TENANT_ID = "11111111-2222-3333-4444-555555555555"


def test_censys_search_hosts():
    response = client.get(
        "/censys/api/v2/hosts/search", params={"q": "services.port:443"}
    )
    assert response.status_code == 200
    result = response.json()["result"]
    assert result["query"] == "services.port:443"
    assert result["hits"]
    # An empty cursor terminates the injector's pagination loop.
    assert result["links"]["next"] == ""
    for hit in result["hits"]:
        assert hit["ip"]
        assert all(service["port"] for service in hit["services"])


def test_censys_search_certificates():
    response = client.get("/censys/api/v2/certificates/search", params={"q": "example"})
    assert response.status_code == 200
    hits = response.json()["result"]["hits"]
    assert hits
    assert all(hit["fingerprint_sha256"] for hit in hits)


def test_shodan_host_search():
    response = client.get(
        "/shodan/shodan/host/search", params={"query": "port:443", "key": "fake"}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == len(body["matches"])
    for match in body["matches"]:
        assert match["ip_str"]
        assert match["port"]


def test_shodan_api_info():
    response = client.get("/shodan/api-info", params={"key": "fake"})
    assert response.status_code == 200
    body = response.json()
    assert body["plan"]
    assert body["usage_limits"]["query_credits"]


def test_slack_chat_post_message():
    response = client.post(
        "/slack/api/chat.postMessage",
        json={"channel": "C123", "text": "hello"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    assert body["channel"] == "C123"
    assert body["message"]["text"] == "hello"


def test_microsoft_openid_configuration_points_at_the_fake_token_endpoint():
    response = client.get(
        f"/microsoft-identity/{TENANT_ID}/v2.0/.well-known/openid-configuration"
    )
    assert response.status_code == 200
    body = response.json()
    assert body["token_endpoint"].endswith(
        f"/microsoft-identity/{TENANT_ID}/oauth2/v2.0/token"
    )
    assert body["issuer"].endswith(f"/{TENANT_ID}/v2.0")


def test_microsoft_token():
    response = client.post(
        f"/microsoft-identity/{TENANT_ID}/oauth2/v2.0/token",
        data={
            "client_id": "client",
            "client_secret": "secret",
            "grant_type": "refresh_token",
            "refresh_token": "refresh",
            "scope": "offline_access ChannelMessage.Send",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "Bearer"
    assert body["access_token"].count(".") == 2
    assert body["scope"] == "offline_access ChannelMessage.Send"


def test_microsoft_graph_send_mail_returns_accepted():
    response = client.post(
        f"/microsoft-graph/v1.0/users/{TENANT_ID}/sendMail",
        json={"message": {"subject": "hello"}},
    )
    assert response.status_code == 202


def test_microsoft_graph_channel_message():
    response = client.post(
        "/microsoft-graph/v1.0/teams/team-1/channels/channel-1/messages",
        json={"body": {"contentType": "html", "content": "<p>hi</p>"}},
    )
    assert response.status_code == 201
    body = response.json()
    assert body["id"]
    assert body["body"]["content"] == "<p>hi</p>"
    assert "team-1" in body["webUrl"]
    assert "from" in body


def test_microsoft_graph_chat_message():
    response = client.post(
        "/microsoft-graph/v1.0/chats/chat-1/messages",
        json={"body": {"contentType": "text", "content": "hi"}},
    )
    assert response.status_code == 201
    assert "chat-1" in response.json()["webUrl"]


def test_google_oauth2_token():
    response = client.post("/google-oauth2/token")
    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "Bearer"
    assert body["access_token"]


def test_gmail_messages_send():
    response = client.post(
        "/gmail/v1/users/me/messages/send", json={"raw": "cmF3IG1lc3NhZ2U="}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["id"]
    assert body["labelIds"] == ["SENT"]


def test_openai_chat_completions_is_defended_by_default():
    response = client.post(
        "/openai/v1/chat/completions",
        json={"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hi"}]},
        headers={"X-OAEV-Inject-Marker": "oaevdeadbeefdeadbeef"},
    )
    assert response.status_code == 200
    content = response.json()["choices"][0]["message"]["content"]
    assert "oaevdeadbeefdeadbeef" not in content


def test_openai_chat_completions_can_leak_the_marker():
    response = client.post(
        "/openai/v1/chat/completions?behaviour=vulnerable",
        json={"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hi"}]},
        headers={"X-OAEV-Inject-Marker": "oaevdeadbeefdeadbeef"},
    )
    assert response.status_code == 200
    content = response.json()["choices"][0]["message"]["content"]
    assert "oaevdeadbeefdeadbeef" in content


def test_anthropic_messages():
    response = client.post(
        "/anthropic/v1/messages?behaviour=vulnerable",
        json={"model": "claude-3-5-sonnet-latest", "messages": []},
        headers={"X-OAEV-Inject-Marker": "oaevdeadbeefdeadbeef"},
    )
    assert response.status_code == 200
    assert "oaevdeadbeefdeadbeef" in response.json()["content"][0]["text"]


def test_echo_reflects_any_request():
    response = client.post("/echo?probe=1", content="mimikyu")
    assert response.status_code == 200
    body = response.json()
    assert body["method"] == "POST"
    assert body["query"] == {"probe": "1"}
    assert body["body"] == "mimikyu"


def test_echo_accepts_get():
    assert client.get("/echo").status_code == 200
