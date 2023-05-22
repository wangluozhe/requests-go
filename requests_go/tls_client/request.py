from json import dumps, loads

from .client import request
from .response import build_response
from ..tls_config import TLSConfig


class Session:
    def __init__(self, tls_config: TLSConfig = None):
        super(Session, self).__init__()
        self.tls_config = tls_config

    def request(self, method, url, params=None, data=None, headers=None, cookies=None, timeout=None, allow_redirects=True,
                proxies=None, verify=None, json=None, body=None, ja3=None, pseudo_header_order=None, tls_extensions=None, http2_extensions=None):
        if self.tls_config.ja3:
            ja3 = self.tls_config.ja3
        if self.tls_config.pseudo_header_order:
            pseudo_header_order = self.tls_config.pseudo_header_order
        if self.tls_config.tls_extensions:
            tls_extensions = self.tls_config.tls_extensions
        if self.tls_config.http2_extensions:
            http2_extensions = self.tls_config.http2_extensions
        if not method and not url and ja3:
            raise Exception("method and url and ja3 must exist")
        request_params = {
            "Method": method,
            "Url": url,
            "Ja3": ja3,
        }
        if params:
            request_params["Params"] = params
        if data:
            request_params["Data"] = data
        if headers:
            request_params["Headers"] = headers
        if cookies:
            request_params["Cookies"] = cookies
        if timeout:
            request_params["Timeout"] = timeout
        if allow_redirects:
            request_params["AllowRedirects"] = allow_redirects
        if proxies:
            request_params["Proxies"] = proxies
        if verify:
            request_params["Verify"] = verify
        if json:
            request_params["Json"] = json
        if body:
            request_params["Body"] = body
        if pseudo_header_order:
            request_params["PseudoHeaderOrder"] = pseudo_header_order
        if tls_extensions:
            request_params["TLSExtensions"] = dumps(tls_extensions, separators=(",", ":"))
        if http2_extensions:
            request_params["HTTP2Extensions"] = dumps(http2_extensions, separators=(",", ":"))
        rs = request(dumps(request_params).encode("utf-8")).decode("utf-8")
        return build_response(loads(rs))
