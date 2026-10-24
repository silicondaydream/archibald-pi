"""The URL fetcher's guard rails, with no network at all.

`socket.getaddrinfo` is replaced with a table, and requests go to an
`httpx.MockTransport` that records what was actually sent. That lets each
promise in fetch.py's docstring be checked directly: which address the
connection went to, which name the Host header and TLS carried, and how many
times a name was resolved.
"""

from __future__ import annotations

import socket
from collections.abc import Callable

import httpx
import pytest

from archibald import fetch as fetch_mod
from archibald.fetch import MAX_BYTES, FetchError, check_url, fetch

PUBLIC = "93.184.215.14"
PUBLIC_2 = "93.184.215.15"


def _resolver(table: dict[str, list[str]], calls: list[str]) -> Callable[..., list[tuple]]:
    def getaddrinfo(host: str, port: int, *_: object, **__: object) -> list[tuple]:
        calls.append(host)
        if host not in table:
            raise socket.gaierror("no such host")
        family = socket.AF_INET6
        return [
            (family if ":" in a else socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, port))
            for a in table[host]
        ]

    return getaddrinfo


@pytest.fixture
def dns(monkeypatch: pytest.MonkeyPatch) -> Callable[[dict[str, list[str]]], list[str]]:
    """Install a fake resolver; returns the list of names it was asked for."""

    def install(table: dict[str, list[str]]) -> list[str]:
        calls: list[str] = []
        monkeypatch.setattr(fetch_mod.socket, "getaddrinfo", _resolver(table, calls))
        return calls

    return install


def _transport(
    handler: Callable[[httpx.Request], httpx.Response], seen: list[httpx.Request]
) -> httpx.MockTransport:
    def record(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    return httpx.MockTransport(record)


def _ok(_: httpx.Request) -> httpx.Response:
    return httpx.Response(200, headers={"content-type": "text/html"}, content=b"<p>hi</p>")


# ----------------------------------------------------------------------
# Refusals
# ----------------------------------------------------------------------


@pytest.mark.parametrize(
    "address",
    ["127.0.0.1", "10.0.0.5", "192.168.1.1", "169.254.169.254", "::1", "fd00::1", "224.0.0.1"],
)
def test_a_name_resolving_to_a_non_public_address_is_refused(dns, address: str) -> None:
    dns({"internal.example": [address]})
    with pytest.raises(FetchError, match="not a public address"):
        check_url("https://internal.example/")


def test_one_private_answer_among_public_ones_is_enough_to_refuse(dns) -> None:
    """What a rebinding setup looks like from here: mixed answers."""
    dns({"mixed.example": [PUBLIC, "127.0.0.1"]})
    with pytest.raises(FetchError, match="not a public address"):
        check_url("https://mixed.example/")


@pytest.mark.parametrize(
    ("url", "message"),
    [
        ("file:///etc/passwd", "Only http"),
        ("ftp://example.com/", "Only http"),
        ("https://user:pw@example.com/", "credentials"),
        ("https:///nohost", "no host"),
        ("https://example.com:22/", "Port 22"),
    ],
)
def test_malformed_or_risky_urls_are_refused_before_resolving(dns, url: str, message: str) -> None:
    calls = dns({"example.com": [PUBLIC]})
    with pytest.raises(FetchError, match=message):
        check_url(url)
    assert calls == []


def test_other_ports_need_an_explicit_opt_in(dns) -> None:
    dns({"example.com": [PUBLIC]})
    assert check_url("https://example.com:8443/", any_port=True).address == PUBLIC


def test_an_unresolvable_name_is_a_fetch_error(dns) -> None:
    dns({})
    with pytest.raises(FetchError, match="Could not resolve"):
        check_url("https://nowhere.example/")


# ----------------------------------------------------------------------
# Pinning
# ----------------------------------------------------------------------


def test_the_connection_goes_to_the_address_that_was_checked(dns) -> None:
    calls = dns({"example.com": [PUBLIC]})
    seen: list[httpx.Request] = []
    body, ctype, final = fetch("https://example.com/page", transport=_transport(_ok, seen))

    (request,) = seen
    assert request.url.host == PUBLIC  # an IP literal: nothing left to resolve
    assert request.headers["host"] == "example.com"
    assert request.extensions["sni_hostname"] == "example.com"  # TLS still checks the name
    assert calls == ["example.com"]  # resolved once, by us
    assert body == b"<p>hi</p>" and "html" in ctype
    assert final == "https://example.com/page"  # reported as the user wrote it


def test_a_non_default_port_is_kept_in_the_host_header(dns) -> None:
    dns({"example.com": [PUBLIC]})
    seen: list[httpx.Request] = []
    fetch("http://example.com:8080/", any_port=True, transport=_transport(_ok, seen))
    assert seen[0].headers["host"] == "example.com:8080"
    assert "sni_hostname" not in seen[0].extensions  # plain http: no TLS name


def test_a_rebinding_answer_on_a_later_lookup_cannot_be_used(dns) -> None:
    """Rebinding needs a second lookup. Pinning means there isn't one per hop."""
    calls = dns({"example.com": [PUBLIC]})
    seen: list[httpx.Request] = []
    fetch("https://example.com/", transport=_transport(_ok, seen))
    assert calls.count("example.com") == 1
    assert all(r.url.host == PUBLIC for r in seen)


# ----------------------------------------------------------------------
# Redirects and limits
# ----------------------------------------------------------------------


def test_every_redirect_hop_is_resolved_checked_and_pinned_again(dns) -> None:
    dns({"a.example": [PUBLIC], "b.example": [PUBLIC_2]})
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.headers["host"] == "a.example":
            return httpx.Response(302, headers={"location": "https://b.example/next"})
        return _ok(request)

    _, _, final = fetch("https://a.example/", transport=_transport(handler, seen))
    assert [r.url.host for r in seen] == [PUBLIC, PUBLIC_2]
    assert seen[1].headers["host"] == "b.example"
    assert final == "https://b.example/next"


def test_a_redirect_into_the_private_network_is_refused(dns) -> None:
    dns({"a.example": [PUBLIC], "metadata.internal": ["169.254.169.254"]})

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "http://metadata.internal/latest/"})

    with pytest.raises(FetchError, match="not a public address"):
        fetch("https://a.example/", transport=_transport(handler, []))


def test_a_relative_redirect_keeps_the_original_name(dns) -> None:
    dns({"a.example": [PUBLIC]})
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(301, headers={"location": "/moved"})
        return _ok(request)

    _, _, final = fetch("https://a.example/", transport=_transport(handler, seen))
    assert final == "https://a.example/moved"
    assert seen[1].headers["host"] == "a.example"


def test_redirect_loops_stop(dns) -> None:
    dns({"a.example": [PUBLIC]})

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "/again"})

    with pytest.raises(FetchError, match="redirects"):
        fetch("https://a.example/", transport=_transport(handler, []))


def test_an_oversized_body_is_cut_off(dns) -> None:
    dns({"big.example": [PUBLIC]})

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"x" * (MAX_BYTES + 1))

    with pytest.raises(FetchError, match="larger than"):
        fetch("https://big.example/", transport=_transport(handler, []))


def test_an_error_status_is_a_fetch_error(dns) -> None:
    dns({"a.example": [PUBLIC]})
    with pytest.raises(FetchError, match="404"):
        fetch(
            "https://a.example/",
            transport=_transport(lambda _: httpx.Response(404), []),
        )
