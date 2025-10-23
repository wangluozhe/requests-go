import io
import base64
import typing
import collections
from json import dumps, loads

from .client import request, freeMemory
from .response import build_response
from ..tls_config import TLSConfig
from .exceptions import TLSClientExeption


def to_bytes(x, encoding=None, errors=None):
    if isinstance(x, bytes):
        return x
    elif not isinstance(x, str):
        raise TypeError(f"not expecting type {type(x).__name__}")
    if encoding or errors:
        return x.encode(encoding or "utf-8", errors=errors or "strict")
    return x.encode()


_METHODS_NOT_EXPECTING_BODY = {"GET", "HEAD", "DELETE", "TRACE", "OPTIONS", "CONNECT"}

class ChunksAndContentLength(typing.NamedTuple):
    chunks: None
    content_length: None


def body_to_chunks(body, method, blocksize) -> ChunksAndContentLength:
    """Takes the HTTP request method, body, and blocksize and
    transforms them into an iterable of chunks to pass to
    socket.sendall() and an optional 'Content-Length' header.

    A 'Content-Length' of 'None' indicates the length of the body
    can't be determined so should use 'Transfer-Encoding: chunked'
    for framing instead.
    """

    chunks: None
    content_length: None

    # No body, we need to make a recommendation on 'Content-Length'
    # based on whether that request method is expected to have
    # a body or not.
    if body is None:
        chunks = None
        if method.upper() not in _METHODS_NOT_EXPECTING_BODY:
            content_length = 0
        else:
            content_length = None

    # Bytes or strings become bytes
    elif isinstance(body, (str, bytes)):
        chunks = (to_bytes(body),)
        content_length = len(chunks[0])

    # File-like object, TODO: use seek() and tell() for length?
    elif hasattr(body, "read"):

        def chunk_readable() -> typing.Iterable[bytes]:
            nonlocal body, blocksize
            encode = isinstance(body, io.TextIOBase)
            while True:
                datablock = body.read(blocksize)
                if not datablock:
                    break
                if encode:
                    datablock = datablock.encode("utf-8")
                yield datablock

        chunks = chunk_readable()
        content_length = None

    # Otherwise we need to start checking via duck-typing.
    else:
        try:
            # Check if the body implements the buffer API.
            mv = memoryview(body)
        except TypeError:
            try:
                # Check if the body is an iterable
                chunks = iter(body)
                content_length = None
            except TypeError:
                raise TypeError(
                    f"'body' must be a bytes-like object, file-like "
                    f"object, or iterable. Instead was {body!r}"
                ) from None
        else:
            # Since it implements the buffer API can be passed directly to socket.sendall()
            chunks = (body,)
            content_length = mv.nbytes

    return ChunksAndContentLength(chunks=chunks, content_length=content_length)


# 将body内容转换为Base64编码
def body_to_base64(body: str or bytes) -> str:
    if type(body) not in [str, bytes]:
        raise TLSClientExeption("Body data is not a string or bytes class.")
    if type(body) is str:
        body = body.encode('utf-8')
    return base64.b64encode(body).decode('utf-8')

class Session:
    def __init__(self, tls_config: TLSConfig = None):
        super(Session, self).__init__()
        self.tls_config = tls_config

    def request(self, method, url, params=None, data=None, headers=None, headers_order=None, un_changed_header_key=None, cookies=None, timeout=None,
                allow_redirects=False, proxies=None, verify=None, cert=None, json=None, body=None, ja3=None, pseudo_header_order=None, tls_extensions=None,
                http2_settings=None, force_http1=False, random_ja3=False):
        id = self.tls_config.get("id", "")
        if self.tls_config.get("ja3", None):
            ja3 = str(self.tls_config["ja3"])
        if self.tls_config.get("random_ja3", None):
            random_ja3 = self.tls_config["random_ja3"]
        if self.tls_config.get("pseudo_header_order", None):
            pseudo_header_order = self.tls_config["pseudo_header_order"]
        if self.tls_config.get("tls_extensions", None):
            tls_extensions = self.tls_config["tls_extensions"]
        if self.tls_config.get("http2_settings", None):
            http2_settings = self.tls_config["http2_settings"]
        if self.tls_config.get("headers_order", None):
            headers_order = [headers_order.lower() for headers_order in self.tls_config["headers_order"]]
        if self.tls_config.get("un_changed_header_key", None):
            un_changed_header_key = [un_changed_header_key.lower() for un_changed_header_key in self.tls_config["un_changed_header_key"]]
        if self.tls_config.get("force_http1", None):
            force_http1 = self.tls_config["force_http1"]
        if not method or not url:
            raise Exception("method and url must exist")
        request_params = {
            "Id": id,
            "Method": method,
            "Url": url,
            "Ja3": ja3,
            "RandomJA3": random_ja3
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
                elif proxies.get("all", ""):
                    request_params["Proxies"] = proxies["all"]
            else:
                request_params["Proxies"] = proxies
        if verify:
            request_params["Verify"] = verify
        if cert:
            request_params["Cert"] = cert
        if body:
            if type(body) in [str, bytes]:
                request_params["Body"] = body_to_base64(body)
            else:
                chunks_and_cl = body_to_chunks(body, method=method, blocksize=16384)
                chunks = chunks_and_cl.chunks
                chunk_bytes = b''
                # If we're given a body we start sending that in chunks.
                if chunks is not None:
                    for chunk in chunks:
                        # Sending empty chunks isn't allowed for TE: chunked
                        # as it indicates the end of the body.
                        if not chunk:
                            continue
                        if isinstance(chunk, str):
                            chunk = chunk.encode("utf-8")
                        chunk_bytes += chunk
                request_params["Body"] = body_to_base64(chunk_bytes)
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
