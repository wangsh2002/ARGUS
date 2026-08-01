from argus_backend.entity_resolution import canonicalize_observation


def test_defanged_ioc_representations_share_stable_canonical_identities() -> None:
    domain = canonicalize_observation("Example[.]COM.", "ioc")
    url = canonicalize_observation("hxxp://Example[.]COM:80/a?x=1", "ioc")
    ipv6 = canonicalize_observation("[2001:0db8:0:0::1]", "infrastructure")
    digest = canonicalize_observation("SHA256:" + "AB" * 32, "ioc")

    assert domain is not None
    assert domain.canonical_key == "domain:example.com"
    assert domain.canonical_value == "example.com"

    assert url is not None
    assert url.canonical_key == "url:http://example.com/a?x=1"
    assert url.canonical_value == "http://example.com/a?x=1"

    assert ipv6 is not None
    assert ipv6.canonical_key == "ipv6:2001:db8::1"

    assert digest is not None
    assert digest.canonical_key == f"sha256:{'ab' * 32}"


def test_related_but_distinct_network_values_are_not_merged() -> None:
    domain = canonicalize_observation("example.com", "ioc")
    url = canonicalize_observation("https://example.com/", "ioc")
    ip = canonicalize_observation("198.51.100.44", "ioc")
    endpoint = canonicalize_observation("198.51.100.44:443", "ioc")

    assert domain is not None and url is not None
    assert domain.canonical_key != url.canonical_key
    assert ip is not None and endpoint is not None
    assert ip.canonical_key != endpoint.canonical_key


def test_named_software_requires_review_before_global_creation() -> None:
    software = canonicalize_observation("Jaguar Tooth", "malware")
    action_label = canonicalize_observation(
        "Jaguar Tooth deployment",
        "malware",
    )

    assert software is not None
    assert software.auto_create is False
    assert action_label is None
