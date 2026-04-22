import json
import re
import time
import base64
import calendar
from typing import Union
from datetime import datetime
from urllib.parse import urlparse
from http.client import responses

from requests.cookies import RequestsCookieJar

from .structures import CaseInsensitiveDict


class Response:
    """object, which contains the response to an HTTP request."""

    def __init__(self):

        # Reference of URL the response is coming from (especially useful with redirects)
        self.url = None

        # Integer Code of responded HTTP Status, e.g. 404 or 200.
        self.status_code = None

        # String of responded HTTP Body.
        self.text = None

        # Case-insensitive Dictionary of Response Headers.
        self.headers = CaseInsensitiveDict()

        # A CookieJar of Cookies the server sent back.
        self.cookies = RequestsCookieJar()

        self._content = False
        self._content_consumed = False

        self.raw = b''

    def __enter__(self):
        return self

    def __repr__(self):
        return f"<Response [{self.status_code}]>"

    def json(self, **kwargs):
        """parse response body to json (dict/list)"""
        return json.loads(self.text, **kwargs)

    @property
    def content(self):
        """Content of the response, in bytes."""

        if self._content is False:
            if self._content_consumed:
                raise RuntimeError("The content for this response was already consumed")

            if self.status_code == 0:
                self._content = None
            else:
                self._content = b"".join(self.iter_content(10 * 1024)) or b""
        self._content_consumed = True
        return self._content

    @property
    def reason(self):
        if self.status_code:
            return responses.get(self.status_code)
        return ""


def _convert_h2_raw_to_h1(raw: bytes, status_code: int) -> bytes:
    """Convert HTTP/2 raw response to HTTP/1.1 format.

    HTTP/2 raw responses use pseudo-headers like `:status: 200` instead of
    the traditional `HTTP/1.1 200 OK` status line. Python's http.client
    (HTTPResponseClient) can only parse HTTP/1.x format, so we need to
    convert the raw data.

    Supported input formats:
      1. Standard HTTP/1.x: `HTTP/1.1 200 OK\\r\\n...`
      2. HTTP/2 with version: `HTTP/2.0 200\\r\\n...`
      3. HTTP/2 pseudo-header: `:status: 200\\r\\n...`
    """
    if not raw:
        # Build a minimal valid HTTP/1.1 response if raw is empty
        reason = responses.get(status_code, "")
        return f"HTTP/1.1 {status_code} {reason}\r\n\r\n".encode("utf-8")

    # Case 1: Already valid HTTP/1.1 format
    if raw.startswith(b"HTTP/1.1 ") or raw.startswith(b"HTTP/1.0 "):
        return raw

    # Case 2: HTTP/2.0 prefix (older Go TLS client format)
    if raw.startswith(b"HTTP/2.0 ") or raw.startswith(b"HTTP/2 "):
        return re.sub(b"^HTTP/2(?:\\.0)? ", b"HTTP/1.1 ", raw, count=1)

    # Case 3: HTTP/2 pseudo-header format `:status: XXX\r\n...`
    if raw.startswith(b":status:"):
        # Split headers from body
        if b"\r\n\r\n" in raw:
            header_block, body = raw.split(b"\r\n\r\n", 1)
        else:
            header_block = raw
            body = b""

        header_lines = header_block.split(b"\r\n")
        new_headers = []
        extracted_status = None

        for line in header_lines:
            if line.startswith(b":status:"):
                # Extract status code from `:status: XXX`
                extracted_status = line.split(b":", 2)[-1].strip()
            elif line.startswith(b":"):
                # Skip other HTTP/2 pseudo-headers (e.g., :authority, :path)
                continue
            else:
                new_headers.append(line)

        # Use extracted status or fall back to the response status_code
        if extracted_status:
            try:
                code = int(extracted_status)
            except ValueError:
                code = status_code
        else:
            code = status_code

        reason = responses.get(code, "")
        status_line = f"HTTP/1.1 {code} {reason}".encode("utf-8")

        # Rebuild the raw response in HTTP/1.1 format
        result = status_line + b"\r\n"
        if new_headers:
            result += b"\r\n".join(new_headers) + b"\r\n"
        result += b"\r\n"
        if body:
            result += body

        return result

    # Fallback: raw doesn't match any known format, synthesize a valid response
    reason = responses.get(status_code, "")
    status_line = f"HTTP/1.1 {status_code} {reason}\r\n".encode("utf-8")
    return status_line + raw


def _parse_cookies(cookie_list, parsed_url, cookie_jar):
    if not cookie_list:
        return
    for cookies in cookie_list:
        name = cookies["Name"]
        value = cookies["Value"]
        path = cookies["Path"]
        domain = cookies["Domain"].lstrip(".") if cookies["Domain"] else parsed_url.hostname
        expires = None
        expires_str = cookies.get("Expires", "")
        if expires_str:
            try:
                dt = datetime.strptime(expires_str, "%Y-%m-%dT%H:%M:%SZ")
                expires = calendar.timegm(dt.timetuple())
            except (ValueError, OverflowError):
                expires = None
        secure = cookies["Secure"]
        http_only = cookies["HttpOnly"]
        rest = {"HttpOnly": http_only}
        cookie_jar.set(
            name=name, value=value, path=path, domain=domain,
            expires=expires, secure=secure, rest=rest, port=None
        )


def build_response(res: Union[dict, list]) -> Response:
    """Builds a Response object """
    response = Response()
    # Add target / url
    response.url = res["url"]
    # Add status code
    response.status_code = res["status_code"]
    # Add headers
    response_headers = {}
    if res["headers"]:
        for header_key, header_values in res["headers"].items():
            response_headers[header_key] = ",".join(header_values)
    response.headers = response_headers
    # Add cookies
    parsed_url = urlparse(response.url)
    _parse_cookies(res.get("cookies"), parsed_url, response.cookies)
    # Add response content (bytes)
    response._content = base64.b64decode(res["content"])
    raw = base64.b64decode(res["raw"])
    response.raw = _convert_h2_raw_to_h1(raw, response.status_code)
    return response


def build_stream_response(meta: dict, stream_body) -> Response:
    """Build a Response for a streaming request.

    Unlike ``build_response`` the body content is *not* loaded eagerly —
    ``response._content`` stays ``False`` so that ``requests``'
    ``iter_content`` / ``iter_lines`` will lazily pull from ``response.raw``.

    Parameters
    ----------
    meta : dict
        The JSON metadata returned by ``stream_request``.  Contains keys:
        ``stream_id``, ``status_code``, ``url``, ``headers``, ``cookies``.
    stream_body : StreamBody
        An ``io.RawIOBase`` wrapper around ``stream_read`` / ``stream_close``.
    """
    response = Response()

    # URL
    response.url = meta.get("url", "")

    # Status code
    response.status_code = meta.get("status_code")

    # Headers
    response_headers = {}
    if meta.get("headers"):
        for header_key, header_values in meta["headers"].items():
            response_headers[header_key] = ",".join(header_values)
    response.headers = response_headers

    # Cookies
    parsed_url = urlparse(response.url)
    _parse_cookies(meta.get("cookies"), parsed_url, response.cookies)

    # Stream ID (useful for diagnostics / manual close)
    response.stream_id = meta.get("stream_id", "")

    # Body — keep _content as False so requests knows to stream
    # We store the raw StreamBody for direct access too
    response._stream_body = stream_body

    # Build a synthetic raw (bytes) for compatibility with the normal
    # HTTP/1.1 parser path — but this is just the status line + headers.
    status_code = response.status_code or 200
    reason_phrase = responses.get(status_code, "")
    status_line = f"HTTP/1.1 {status_code} {reason_phrase}\r\n"
    header_lines = ""
    for k, v in response_headers.items():
        header_lines += f"{k}: {v}\r\n"
    synthetic_raw = (status_line + header_lines + "\r\n").encode("utf-8")
    response.raw = synthetic_raw

    return response
