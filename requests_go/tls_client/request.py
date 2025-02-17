import collections
from json import dumps, loads

from .client import request, freeMemory
from .response import build_response
from ..tls_config import TLSConfig
from .exceptions import TLSClientExeption


class Session:
    def __init__(self, tls_config: TLSConfig = None):
        super(Session, self).__init__()
        self.tls_config = tls_config

    def request(self, method, url, params=None, data=None, headers=None, headers_order=None, un_changed_header_key=None, cookies=None, timeout=None,
                allow_redirects=False, proxies=None, verify=None, cert=None, json=None, body=None, ja3=None, pseudo_header_order=None, tls_extensions=None,
                http2_settings=None, force_http1=False):
        id = self.tls_config.get("id", "")
        if self.tls_config.get("ja3", None):
            ja3 = str(self.tls_config["ja3"])
        if self.tls_config.get("pseudo_header_order", None):
            pseudo_header_order = self.tls_config["pseudo_header_order"]
        if self.tls_config.get("tls_extensions", None):
            tls_extensions = self.tls_config["tls_extensions"]
        if self.tls_config.get("http2_settings", None):
            http2_settings = self.tls_config["http2_settings"]
        if self.tls_config.get("headers_order", None):
            headers_order = self.tls_config["headers_order"]
        if self.tls_config.get("un_changed_header_key", None):
            un_changed_header_key = self.tls_config["un_changed_header_key"]
        if self.tls_config.get("force_http1", None):
            force_http1 = self.tls_config["force_http1"]
        if not method and not url and ja3:
            raise Exception("method and url and ja3 must exist")
        request_params = {
            "Id": id,
            "Method": method,
            "Url": url,
            "Ja3": ja3,
        }
        if params:
            request_params["Params"] = params
        if headers:
            if type(headers) == collections.OrderedDict:
                headers = dict(headers)
            headers_tmp = loads(dumps(headers))
            for key, value in headers_tmp.items():
                if key.lower() == "content-length":
                    headers.pop(key)
            request_params["Headers"] = headers
        if headers_order:
            request_params["HeadersOrder"] = headers_order
        if headers_order:
            request_params["UnChangedHeaderKey"] = un_changed_header_key
        if cookies:
            request_params["Cookies"] = cookies
        if timeout:
            if type(timeout) in [list, tuple]:
                request_params["Timeout"] = timeout[0]
            elif type(timeout) in [int, float]:
                request_params["Timeout"] = int(timeout)
        request_params["AllowRedirects"] = allow_redirects
        if proxies:
            if type(proxies) == collections.OrderedDict:
                proxies = dict(proxies)
            if type(proxies) == dict:
                if proxies.get("https", "") and url.startswith("https:"):
                    request_params["Proxies"] = proxies["https"]
                elif proxies.get("http", "") and url.startswith("http:"):
                    request_params["Proxies"] = proxies["http"]
            else:
                request_params["Proxies"] = proxies
        if verify:
            request_params["Verify"] = verify
        if cert:
            request_params["Cert"] = cert
        if body:
            if type(body) == str:
                request_params["Body"] = body
            elif type(body) == bytes:
                request_params["Body"] = body.decode()
            else:
                raise TLSClientExeption("Body data is not a string or bytes class.")
        elif data:
            request_params["Data"] = data
        elif json:
            request_params["Json"] = json
        if force_http1:
            request_params["ForceHTTP1"] = force_http1
        if pseudo_header_order:
            request_params["PseudoHeaderOrder"] = pseudo_header_order
        if tls_extensions:
            request_params["TLSExtensions"] = dumps(tls_extensions.toMap(), separators=(",", ":"))
        if http2_settings:
            request_params["HTTP2Settings"] = dumps(http2_settings.toMap(), separators=(",", ":"))
        rs = request(dumps(request_params).encode("utf-8")).decode("utf-8")
        try:
            res = loads(rs)
            if res.get("err", ""):
                raise TLSClientExeption(res["err"])
            freeMemory(res["id"].encode("utf-8"))
            return build_response(res)
        except Exception as e:
            raise TLSClientExeption("requests_go error:", rs)
