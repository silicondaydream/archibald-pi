"""Fetch a page to scan it — without becoming a way into your network.

A "scan this URL" box is a server-side request forgery primitive unless it is
careful, so this is:

* http and https only, no credentials in the URL;
* ports 80 and 443 only, unless the caller opts in;
* public addresses only: every address the host resolves to must be globally
  routable — no loopback, RFC 1918, link-local (cloud metadata lives there),
  multicast or reserved ranges;
* **pinned to the address that was checked**: the connection goes to that IP,
  with the original name sent as the Host header and as the TLS server name, so
  the certificate is still verified against the name. There is no second lookup,
  so a DNS-rebinding server has nothing to rebind;
* redirects followed by hand, re-resolving, re-checking and re-pinning every hop,
  at most five;
* no proxy settings from the environment, and no connection reuse between hops;
* 10 seconds and 5 MB, whichever comes first.

The page is downloaded and parsed. It is never rendered, and its scripts never run.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

import httpx

from archibald import __version__

MAX_BYTES = 5_000_000
TIMEOUT = 10.0
MAX_REDIRECTS = 5
DEFAULT_PORTS = frozenset({80, 443})
USER_AGENT = f"Archibald/{__version__} (prompt-injection scanner; +local)"


class FetchError(Exception):
    """A URL we will not fetch, or could not."""


@dataclass(frozen=True)
class Target:
    """A URL that passed every check, and the address it is pinned to."""

    url: httpx.URL
    address: str


def check_url(url: str, *, any_port: bool = False) -> Target:
    """Validate a URL and resolve it once. Raises FetchError on any refusal."""
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise FetchError("Only http:// and https:// URLs can be scanned")
    if not parts.hostname:
        raise FetchError("That URL has no host")
    if parts.username or parts.password:
        raise FetchError("URLs with embedded credentials are refused")
    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError as exc:
        raise FetchError("That URL has an invalid port") from exc
    if not any_port and port not in DEFAULT_PORTS:
        raise FetchError(f"Port {port} is refused; only 80 and 443 are scanned by default")

    try:
        infos = socket.getaddrinfo(parts.hostname, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise FetchError(f"Could not resolve {parts.hostname}") from exc
    if not infos:
        raise FetchError(f"Could not resolve {parts.hostname}")

    # Every answer must be public, not just the one we will use: a name that
    # resolves to one public and one private address is exactly what a
    # rebinding attack looks like from here.
    addresses = []
    for info in infos:
        address = ipaddress.ip_address(str(info[4][0]).split("%")[0])
        if not address.is_global or address.is_multicast:
            raise FetchError(
                f"{parts.hostname} resolves to {address}, which is not a public address"
            )
        addresses.append(str(address))
    return Target(url=httpx.URL(url), address=addresses[0])


def _pinned(target: Target) -> tuple[httpx.URL, dict[str, str], dict[str, str]]:
    """The request to send: to the checked IP, but as the original host."""
    url = target.url
    pinned = url.copy_with(host=target.address)
    # netloc keeps a non-default port, which is what a Host header should carry.
    headers = {"Host": url.netloc.decode("ascii")}
    # httpcore uses this as the TLS server name, so SNI and certificate
    # verification are both against the name, never the bare address.
    extensions = {"sni_hostname": url.host} if url.scheme == "https" else {}
    return pinned, headers, extensions


def fetch(
    url: str, *, any_port: bool = False, transport: httpx.BaseTransport | None = None
) -> tuple[bytes, str, str]:
    """(body, content-type, final URL). `transport` is for tests."""
    headers = {"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml,*/*;q=0.8"}
    with httpx.Client(
        follow_redirects=False,
        timeout=TIMEOUT,
        trust_env=False,
        headers=headers,
        # A pooled connection is keyed by IP. Reusing one opened for another
        # name on the same address would skip that name's certificate check.
        limits=httpx.Limits(max_keepalive_connections=0),
        transport=transport,
    ) as client:
        for _ in range(MAX_REDIRECTS + 1):
            target = check_url(url, any_port=any_port)
            pinned, host_header, extensions = _pinned(target)
            try:
                with client.stream(
                    "GET", pinned, headers=host_header, extensions=extensions
                ) as response:
                    if response.is_redirect:
                        location = response.headers.get("location")
                        if not location:
                            raise FetchError("Redirect without a Location header")
                        # Joined against the URL as the user wrote it, not the
                        # pinned one, so a relative redirect keeps the hostname.
                        url = urljoin(str(target.url), location)
                        continue
                    if response.status_code >= 400:
                        raise FetchError(f"The server answered {response.status_code}")
                    body = bytearray()
                    for chunk in response.iter_bytes():
                        body.extend(chunk)
                        if len(body) > MAX_BYTES:
                            raise FetchError(f"Page is larger than {MAX_BYTES // 1_000_000} MB")
                    return bytes(body), response.headers.get("content-type", ""), str(target.url)
            except httpx.HTTPError as exc:
                raise FetchError(f"Could not fetch the page ({exc.__class__.__name__})") from exc
    raise FetchError(f"More than {MAX_REDIRECTS} redirects")
