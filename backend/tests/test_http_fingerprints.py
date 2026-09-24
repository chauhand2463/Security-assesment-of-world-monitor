"""Regression tests for HTTP/TLS fingerprint helpers (app.http.fingerprints).

The critical case: ``ssl.SSLSocket.getpeercert()`` returns ``subject`` /
``issuer`` as RDN groups where a single-attribute group is a 1-tuple, e.g.
``(('commonName', 'localhost'),)``.  The original ``_name_tuple`` indexed
``part[1]`` blindly and raised ``IndexError: tuple index out of range`` during
any HTTPS health/discovery probe (the Phase 11 discovery regression).
"""
from app.http.fingerprints import _is_expired, _name_tuple, host_of, port_of


def test_name_tuple_single_attribute_rdn_group():
    # Exact shape returned by getpeercert() for a typical localhost cert.
    raw = ((("commonName", "localhost"),),)
    assert _name_tuple(raw) == [["commonName", "localhost"]]


def test_name_tuple_multiple_rdn_groups():
    raw = (
        (("commonName", "example.com"),),
        (("organizationName", "Example Org"),),
        (("countryName", "US"),),
    )
    assert _name_tuple(raw) == [
        ["commonName", "example.com"],
        ["organizationName", "Example Org"],
        ["countryName", "US"],
    ]


def test_name_tuple_multi_valued_rdn_group():
    # A multi-valued RDN packs several pairs inside one group.
    raw = ((("commonName", "a.example"), ("serialNumber", "001")),)
    assert _name_tuple(raw) == [
        ["commonName", "a.example"],
        ["serialNumber", "001"],
    ]


def test_name_tuple_never_raises_on_malformed_input():
    assert _name_tuple(None) == []
    assert _name_tuple(()) == []
    assert _name_tuple(((),)) == []
    assert _name_tuple(("not-a-tuple",)) == []
    # Truncated pair (only one element) must be skipped, not indexed.
    assert _name_tuple((("commonName",),)) == []
    assert _name_tuple(((None,),)) == []


def test_name_tuple_scalar_values_coerced_to_str():
    raw = (((1, 2),),)
    assert _name_tuple(raw) == [["1", "2"]]


def test_is_expired_and_unparseable():
    assert _is_expired(None) is None
    assert _is_expired("garbage-date") is None
    assert _is_expired("Jan  1 00:00:00 2000 GMT") is True
    assert _is_expired("Jan  1 00:00:00 2999 GMT") is False


def test_host_of_and_port_of():
    assert host_of("https://Example.COM/path") == "example.com"
    assert host_of("") == ""
    assert port_of("https://example.com", 443) == 443
    assert port_of("http://example.com", 80) == 80
    assert port_of("http://example.com:8080", 80) == 8080
    assert port_of("ftp://example.com", 21) == 21
