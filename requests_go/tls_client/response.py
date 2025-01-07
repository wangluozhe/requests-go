import json
import time
import base64
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
    if res["cookies"]:
        for cookies in res["cookies"]:
            name = cookies["Name"]
            value = cookies["Value"]
            path = cookies["Path"]
            domain = cookies["Domain"] if cookies["Domain"] else parsed_url.hostname
            expires = int(time.time()) + (datetime.strptime(cookies["Expires"], "%Y-%m-%dT%H:%M:%SZ") - datetime.now()).seconds
            secure = cookies["Secure"]
            http_only = cookies["HttpOnly"]
            rest = {
                "HttpOnly": http_only
            }
            response.cookies.set(name=name, value=value, path=path, domain=domain, expires=expires, secure=secure, rest=rest, port=None)
    # Add response content (bytes)
    response._content = base64.b64decode(res["content"])
    return response
