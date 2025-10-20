from api.hunt_io import (
    Malware,
    C2Feed,
    C2FeedExtraFactory,
)


def test_c2feed_dataclass_and_to_dict():
    """
    Tests the C2Feed dataclass and its to_dict method.
    """
    malware = Malware(name="Cobalt Strike", subsystem="Team Server")
    extra = C2FeedExtraFactory.build()  # Use factory to build a test instance
    c2_feed = C2Feed(
        ip="1.2.3.4",
        hostname="evil.com",
        scan_uri="https://evil.com/scan",
        timestamp="2023-10-27T10:00:00Z",
        port=8080,
        malware=malware,
        extra=extra,
        confidence=95,
    )

    # Test dataclass attributes
    assert c2_feed.ip == "1.2.3.4"
    assert c2_feed.hostname == "evil.com"
    assert c2_feed.port == 8080
    assert c2_feed.confidence == 95
    assert c2_feed.malware.name == "Cobalt Strike"
    assert c2_feed.malware.subsystem == "Team Server"
    assert c2_feed.extra == extra

    # Test the to_dict method
    c2_dict = c2_feed.to_dict()

    assert c2_dict["ip"] == "1.2.3.4"
    assert c2_dict["hostname"] == "evil.com"
    assert c2_dict["port"] == 8080
    assert c2_dict["confidence"] == 95
    assert c2_dict["extra"]["status_code"] == extra.status_code  # Check a nested value

    # Check that the malware object was flattened correctly
    assert "malware" not in c2_dict
    assert c2_dict["malware_name"] == "Cobalt Strike"
    assert c2_dict["malware_subsystem"] == "Team Server"
