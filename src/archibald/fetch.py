"""Fetch a page to scan it — without becoming a way into your network.

A "scan this URL" box is a server-side request forgery primitive unless it is
careful, so this is:

* http and https only, no credentials in the URL;
* public addresses only: every address the host resolves to must be globally
  routable — no loopback, RFC 1918, link-local (cloud metadata lives there),
  multicast or reserved ranges;
* redirects followed by hand, re-checking every hop, at most five;
* no proxy settings from the environment;
* 10 seconds and 5 MB, whichever comes first.

The page is downloaded and parsed. It is never rendered, and its scripts never run.

Known limit: the address is checked, then httpx resolves the name again to
connect, so a DNS-rebinding server could answer differently the second time. The
server binds to loopback by default, which is what keeps that from mattering;
pinning the connection to the checked address is on the task list.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urljoin, urlsplit

import httpx

from archibald import __version__

MAX_BYTES = 5_000_000
TIMEOUT = 10.0
MAX_REDIRECTS = 5
USER_AGENT = f"Archibald/{__version__} (prompt-injection scanner; +local)"


class FetchError(Exception):
    """A URL we will not fetch, or could not."""


def check_url(url: str) -> None:
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise FetchError("Only http:// and https:// URLs can be scanned")
    if not parts.hostname:
        raise FetchError("That URL has no host")
    if parts.username or parts.password:
        raise FetchError("URLs with embedded credentials are refused")
    try:
        infos = socket.getaddrinfo(parts.hostname, parts.port or None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise FetchError(f"Could not resolve {parts.hostname}") from exc
    for info in infos:
        address = ipaddress.ip_address(str(info[4][0]).split("%")[0])
        if not address.is_global or address.is_multicast:
            raise FetchError(
                f"{parts.hostname} resolves to {address}, which is not a public address"
            )


def fetch(url: str) -> tuple[bytes, str, str]:
    """(body, content-type, final URL)."""
    headers = {"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml,*/*;q=0.8"}
    with httpx.Client(
        follow_redirects=False, timeout=TIMEOUT, trust_env=False, headers=headers
    ) as client:
        for _ in range(MAX_REDIRECTS + 1):
            check_url(url)
            try:
                with client.stream("GET", url) as response:
                    if response.is_redirect:
                        location = response.headers.get("location")
                        if not location:
                            raise FetchError("Redirect without a Location header")
                        url = urljoin(url, location)
                        continue
                    if response.status_code >= 400:
                        raise FetchError(f"The server answered {response.status_code}")
                    body = bytearray()
                    for chunk in response.iter_bytes():
                        body.extend(chunk)
                        if len(body) > MAX_BYTES:
                            raise FetchError(f"Page is larger than {MAX_BYTES // 1_000_000} MB")
                    return bytes(body), response.headers.get("content-type", ""), url
            except httpx.HTTPError as exc:
                raise FetchError(f"Could not fetch the page ({exc.__class__.__name__})") from exc
    raise FetchError(f"More than {MAX_REDIRECTS} redirects")
