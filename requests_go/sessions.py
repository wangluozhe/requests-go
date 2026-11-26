import copy
import asyncio
import threading
from collections import OrderedDict

import requests
from requests import Request
from requests.hooks import default_hooks
from requests.utils import default_headers
from requests.models import DEFAULT_REDIRECT_LIMIT
from requests.cookies import cookiejar_from_dict
from requests.adapters import HTTPAdapter

from .adapters import TLSAdapter
# import private tls_config
try:
    from tls_config import TLSConfig
except ImportError:
    from .tls_config.config import TLSConfig
from .tls_client.client import freeSession


class _NativeSession:
    """Keep the DLL session alive while a request or its response body uses it."""

    def __init__(self, session_id):
        self.id = session_id
        self._lock = threading.Lock()
        self._active = 0
        self._closed = True

    def acquire(self):
        with self._lock:
            self._active += 1
            self._closed = False

    def release(self):
        with self._lock:
            self._active -= 1
            self._free_if_unused()

    def close(self):
        with self._lock:
            if not self._closed:
                self._closed = True
                self._free_if_unused()

    def _free_if_unused(self):
        if self._closed and self._active == 0:
            freeSession(self.id.encode("utf-8"))


class Session(requests.Session):
    """A Requests session.

    Provides cookie persistence, connection-pooling, and configuration.

    Basic Usage::

      >>> import requests
      >>> s = requests.Session()
      >>> s.get('https://httpbin.org/get')
      <Response [200]>

    Or as a context manager::

      >>> with requests.Session() as s:
      ...     s.get('https://httpbin.org/get')
      <Response [200]>
    """

    __attrs__ = [
        "headers",
        "cookies",
        "auth",
        "proxies",
        "hooks",
        "params",
        "verify",
        "cert",
        "adapters",
        "stream",
        "trust_env",
        "max_redirects",
    ]

    def __init__(self):
        #: A case-insensitive dictionary of headers to be sent on each
        #: :class:`Request <Request>` sent from this
        #: :class:`Session <Session>`.
        self.headers = default_headers()

        #: Default Authentication tuple or object to attach to
        #: :class:`Request <Request>`.
        self.auth = None

        #: Dictionary mapping protocol or protocol and host to the URL of the proxy
        #: (e.g. {'http': 'foo.bar:3128', 'http://host.name': 'foo.bar:4012'}) to
        #: be used on each :class:`Request <Request>`.
        self.proxies = {}

        #: Event-handling hooks.
        self.hooks = default_hooks()

        #: Dictionary of querystring data to attach to each
        #: :class:`Request <Request>`. The dictionary values may be lists for
        #: representing multivalued query parameters.
        self.params = {}

        #: Stream response content default.
        self.stream = False

        #: SSL Verification default.
        #: Defaults to `True`, requiring requests to verify the TLS certificate at the
        #: remote end.
        #: If verify is set to `False`, requests will accept any TLS certificate
        #: presented by the server, and will ignore hostname mismatches and/or
        #: expired certificates, which will make your application vulnerable to
        #: man-in-the-middle (MitM) attacks.
        #: Only set this to `False` for testing.
        self.verify = True

        #: SSL client certificate default, if String, path to ssl client
        #: cert file (.pem). If Tuple, ('cert', 'key') pair.
        self.cert = None

        #: Maximum number of redirects allowed. If the request exceeds this
        #: limit, a :class:`TooManyRedirects` exception is raised.
        #: This defaults to requests.models.DEFAULT_REDIRECT_LIMIT, which is
        #: 30.
        self.max_redirects = DEFAULT_REDIRECT_LIMIT

        #: Trust environment settings for proxy configuration, default
        #: authentication and similar.
        self.trust_env = True

        #: A CookieJar containing all currently outstanding cookies set on this
        #: session. By default it is a
        #: :class:`RequestsCookieJar <requests.cookies.RequestsCookieJar>`, but
        #: may be any other ``cookielib.CookieJar`` compatible object.
        self.cookies = cookiejar_from_dict({})

        #: This default to random_tls_config.
        self._tls_config = TLSConfig()
        self._native_session = _NativeSession(self._tls_config.id)

        # Default connection adapters.
        self.adapters = OrderedDict()
        if self._tls_config.ja3:
            config = self._clone_tls_config(self.tls_config)
            self.mount("https://", TLSAdapter(tls_config=config, native_session=self._native_session))
        else:
            self.mount("https://", HTTPAdapter())
        self.mount("http://", HTTPAdapter())

    @property
    def tls_config(self):
        return self._tls_config

    @tls_config.setter
    def tls_config(self, value):
        self._tls_config = self._clone_tls_config(value)

    def _clone_tls_config(self, value):
        if isinstance(value, TLSConfig):
            config = copy.deepcopy(value)
        else:
            if hasattr(value, "toJSON"):
                value = value.toJSON()
            if not isinstance(value, dict):
                raise TypeError("tls_config must be of type dict or TLSConfig.")
            config = TLSConfig().fromJSON(copy.deepcopy(value))
        config.id = self._native_session.id
        return config

    def request(
            self,
            method,
            url,
            params=None,
            data=None,
            headers=None,
            cookies=None,
            files=None,
            auth=None,
            timeout=None,
            allow_redirects=True,
            proxies=None,
            hooks=None,
            stream=None,
            verify=None,
            cert=None,
            json=None,
            tls_config=None,
    ):
        """Constructs a :class:`Request <Request>`, prepares it and sends it.
        Returns :class:`Response <Response>` object.

        :param method: method for the new :class:`Request` object.
        :param url: URL for the new :class:`Request` object.
        :param params: (optional) Dictionary or bytes to be sent in the query
            string for the :class:`Request`.
        :param data: (optional) Dictionary, list of tuples, bytes, or file-like
            object to send in the body of the :class:`Request`.
        :param json: (optional) json to send in the body of the
            :class:`Request`.
        :param headers: (optional) Dictionary of HTTP Headers to send with the
            :class:`Request`.
        :param cookies: (optional) Dict or CookieJar object to send with the
            :class:`Request`.
        :param files: (optional) Dictionary of ``'filename': file-like-objects``
            for multipart encoding upload.
        :param auth: (optional) Auth tuple or callable to enable
            Basic/Digest/Custom HTTP Auth.
        :param timeout: (optional) How long to wait for the server to send
            data before giving up, as a float, or a :ref:`(connect timeout,
            read timeout) <timeouts>` tuple.
        :type timeout: float or tuple
        :param allow_redirects: (optional) Set to True by default.
        :type allow_redirects: bool
        :param proxies: (optional) Dictionary mapping protocol or protocol and
            hostname to the URL of the proxy.
        :param stream: (optional) whether to immediately download the response
            content. Defaults to ``False``.
        :param verify: (optional) Either a boolean, in which case it controls whether we verify
            the server's TLS certificate, or a string, in which case it must be a path
            to a CA bundle to use. Defaults to ``True``. When set to
            ``False``, requests will accept any TLS certificate presented by
            the server, and will ignore hostname mismatches and/or expired
            certificates, which will make your application vulnerable to
            man-in-the-middle (MitM) attacks. Setting verify to ``False``
            may be useful during local development or testing.
        :param cert: (optional) if String, path to ssl client cert file (.pem).
            If Tuple, ('cert', 'key') pair.
        :param tls_config: (optional) Dictionary, tls-client config params. If None, random tls. Default None.
        :rtype: requests.Response
        """
        def _ensure_https_adapter(adapter):
            current = self.adapters.get("https://")
            if type(current) is type(adapter):
                if isinstance(adapter, TLSAdapter):
                    current_cfg = getattr(current, "_tls_config", None)
                    target_cfg = getattr(adapter, "_tls_config", None)
                    if current._native_session is self._native_session and current_cfg == target_cfg:
                        return
                else:
                    return
            self.mount("https://", adapter)

        if url.startswith("https://") and (tls_config or str(self.tls_config.ja3) != "None"):
            config = self._clone_tls_config(tls_config or self.tls_config)
            _ensure_https_adapter(TLSAdapter(tls_config=config, native_session=self._native_session))
        else:
            _ensure_https_adapter(HTTPAdapter())
        # Create the Request.
        req = Request(
            method=method.upper(),
            url=url,
            headers=headers,
            files=files,
            data=data or {},
            json=json,
            params=params or {},
            auth=auth,
            cookies=cookies,
            hooks=hooks,
        )
        prep = self.prepare_request(req)

        proxies = proxies or {}

        settings = self.merge_environment_settings(
            prep.url, proxies, stream, verify, cert
        )

        # Send the request.
        send_kwargs = {
            "timeout": timeout,
            "allow_redirects": allow_redirects,
        }
        send_kwargs.update(settings)

        resp = self.send(prep, **send_kwargs)
        self.cookies.update(resp.cookies)  # session更新cookies

        return resp

    def close(self):
        try:
            super().close()
        finally:
            self._native_session.close()

    def __del__(self):
        try:
            self._native_session.close()
        except Exception:
            pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self.close)


class AsyncSession(Session):
    """A Requests async session.

    Thread safety: each async_request creates an independent temporary Session
    that owns its own adapters and cookies, avoiding shared mutable state
    during the request. Response cookies are merged back under a lock.
    """

    def __init__(self):
        super().__init__()
        self._cookie_lock = threading.Lock()

    async def get(self, url, **kwargs):
        r"""Sends a GET request. Returns :class:`Response` object.

        :param url: URL for the new :class:`Request` object.
        :param \*\*kwargs: Optional arguments that ``request`` takes.
        :rtype: requests.Response
        """

        kwargs.setdefault("allow_redirects", True)
        return await self.async_request("GET", url, **kwargs)

    async def options(self, url, **kwargs):
        r"""Sends a OPTIONS request. Returns :class:`Response` object.

        :param url: URL for the new :class:`Request` object.
        :param \*\*kwargs: Optional arguments that ``request`` takes.
        :rtype: requests.Response
        """

        kwargs.setdefault("allow_redirects", True)
        return await self.async_request("OPTIONS", url, **kwargs)

    async def head(self, url, **kwargs):
        r"""Sends a HEAD request. Returns :class:`Response` object.

        :param url: URL for the new :class:`Request` object.
        :param \*\*kwargs: Optional arguments that ``request`` takes.
        :rtype: requests.Response
        """

        kwargs.setdefault("allow_redirects", False)
        return await self.async_request("HEAD", url, **kwargs)

    async def post(self, url, data=None, json=None, **kwargs):
        r"""Sends a POST request. Returns :class:`Response` object.

        :param url: URL for the new :class:`Request` object.
        :param data: (optional) Dictionary, list of tuples, bytes, or file-like
            object to send in the body of the :class:`Request`.
        :param json: (optional) json to send in the body of the :class:`Request`.
        :param \*\*kwargs: Optional arguments that ``request`` takes.
        :rtype: requests.Response
        """

        return await self.async_request("POST", url, data=data, json=json, **kwargs)

    async def put(self, url, data=None, **kwargs):
        r"""Sends a PUT request. Returns :class:`Response` object.

        :param url: URL for the new :class:`Request` object.
        :param data: (optional) Dictionary, list of tuples, bytes, or file-like
            object to send in the body of the :class:`Request`.
        :param \*\*kwargs: Optional arguments that ``request`` takes.
        :rtype: requests.Response
        """

        return await self.async_request("PUT", url, data=data, **kwargs)

    async def patch(self, url, data=None, **kwargs):
        r"""Sends a PATCH request. Returns :class:`Response` object.

        :param url: URL for the new :class:`Request` object.
        :param data: (optional) Dictionary, list of tuples, bytes, or file-like
            object to send in the body of the :class:`Request`.
        :param \*\*kwargs: Optional arguments that ``request`` takes.
        :rtype: requests.Response
        """

        return await self.async_request("PATCH", url, data=data, **kwargs)

    async def delete(self, url, **kwargs):
        r"""Sends a DELETE request. Returns :class:`Response` object.

        :param url: URL for the new :class:`Request` object.
        :param \*\*kwargs: Optional arguments that ``request`` takes.
        :rtype: requests.Response
        """

        return await self.async_request("DELETE", url, **kwargs)

    def _create_temp_session(self):
        """Create a temporary Session that inherits settings from this AsyncSession.

        The temp session has its OWN adapters dict and its own copy of cookies,
        so concurrent threads do not race on shared state.
        """
        tmp = Session()
        tmp.headers = self.headers.copy()
        tmp.auth = self.auth
        tmp.proxies = self.proxies.copy() if self.proxies else {}
        tmp.params = self.params.copy() if self.params else {}
        tmp.hooks = {k: list(v) for k, v in self.hooks.items()}
        tmp.verify = self.verify
        tmp.cert = self.cert
        tmp.stream = self.stream
        tmp.trust_env = self.trust_env
        tmp.max_redirects = self.max_redirects

        with self._cookie_lock:
            tmp.cookies = copy.copy(self.cookies)

        tmp.tls_config = self.tls_config

        return tmp

    def loop_request(self, arguments):
        """Run a request on a temporary session to avoid shared mutable state."""
        tmp = self._create_temp_session()
        try:
            resp = tmp.request(**arguments)
            if resp.cookies:
                with self._cookie_lock:
                    self.cookies.update(resp.cookies)
            return resp
        finally:
            try:
                tmp.close()
            except Exception:
                pass

    async def async_request(
        self,
        method,
        url,
        params=None,
        data=None,
        headers=None,
        cookies=None,
        files=None,
        auth=None,
        timeout=None,
        allow_redirects=True,
        proxies=None,
        hooks=None,
        stream=None,
        verify=None,
        cert=None,
        json=None,
        tls_config=None,
    ):
        kwargs = {
            "method": method,
            "url": url,
            "params": params,
            "data": data,
            "headers": headers,
            "cookies": cookies,
            "files": files,
            "auth": auth,
            "timeout": timeout,
            "allow_redirects": allow_redirects,
            "proxies": proxies,
            "hooks": hooks,
            "stream": stream,
            "verify": verify,
            "cert": cert,
            "json": json,
            "tls_config": tls_config,
        }
        loop = asyncio.get_running_loop()
        response = await loop.run_in_executor(None, self.loop_request, kwargs)
        return response


def session():
    """
    Returns a :class:`Session` for context-management.

    .. deprecated:: 1.0.0

        This method has been deprecated since version 1.0.0 and is only kept for
        backwards compatibility. New code should use :class:`~requests.sessions.Session`
        to create a session. This may be removed at a future date.

    :rtype: Session
    """
    return Session()


def async_session():
    """
    Returns a :class:`AsyncSession` for context-management.

    .. deprecated:: 1.0.0

        This method has been deprecated since version 1.0.0 and is only kept for
        backwards compatibility. New code should use :class:`~requests.sessions.AsyncSession`
        to create a session. This may be removed at a future date.

    :rtype: AsyncSession
    """
    return AsyncSession()
