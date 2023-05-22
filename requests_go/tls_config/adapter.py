import json

from requests import Response, PreparedRequest
from requests.exceptions import RequestException
from requests.utils import select_proxy
from requests.adapters import (
	BaseAdapter,
	DEFAULT_RETRIES,
	DEFAULT_POOLSIZE,
	DEFAULT_POOLBLOCK,
)
from urllib3.util.retry import Retry
from urllib3.exceptions import MaxRetryError

from .config import TLSConfig
from ..pool_provider import TLSPoolProvider


class TLSAdapter(BaseAdapter):
	def __init__(
			self,
			tls_config: TLSConfig = None,
			max_retries=DEFAULT_RETRIES,
			max_pools_count=DEFAULT_POOLSIZE,
			max_pool_size=DEFAULT_POOLSIZE,
			pool_block=DEFAULT_POOLBLOCK,
			pool_provider_factory=TLSPoolProvider,
			verbose=0
	):
		super(TLSAdapter, self).__init__()
		self._verbose = verbose
		self._tls_config = tls_config
		if max_retries == DEFAULT_RETRIES:
			self.max_retries = Retry(0, read=False)
		else:
			self.max_retries = Retry.from_int(max_retries)

		self._pool_provider = pool_provider_factory(
			max_pools=max_pools_count,
			max_pool_size=max_pool_size,
			pool_block=pool_block,
			tls_config=tls_config
		)

	def send(self, request: PreparedRequest, stream=False, timeout=None, verify=True, cert=None, proxies=None) -> Response:
		"""Sends PreparedRequest object using request.TLSRequest. Returns Response object.

        Args:
            request (PreparedRequest): the request being sent.
            stream (bool, optional): Defaults to False. Whether to stream the
                request content.
            timeout (float, optional): Defaults to None. How many seconds to
                wait for the server to send data before giving up, as a float,
                or a `(connect timeout, read timeout)` tuple.
            verify (bool, optional): Defaults to True. Either a boolean, in
                which case it controls whether we verify the server's TLS
                certificate, or a string, in which case it must be a path
                to a CA bundle to use.
            cert (str, optional): Defaults to None. Any user-provided SSL
                certificate to be trusted.
            proxies (dict,  optional): Defaults to None. The proxies
                dictionary to apply to the request.

        Raises:
            requests.exceptions.SSLError: if request failed due to a SSL error.
            requests.exceptions.ProxyError: if request failed due to a proxy error.
            requests.exceptions.ConnectTimeout: if request failed due to a connection timeout.
            requests.exceptions.ReadTimeout: if request failed due to a read timeout.
            requests.exceptions.ConnectionError: if there is a problem with the
                connection (default error).

        Returns:
            request.Response: the response to the request.
        """
		# response = self._session.execute_request(
		# 	method=request.method,
		# 	url=request.url,
		# 	headers=request.headers,
		# 	insecure_skip_verify=verify,
		# 	timeout_seconds=timeout,
		# 	proxy=proxies,
		# )
		# tls_response = build_response(response)
		# return tls_response
		retries = self.max_retries

		try:
			while not retries.is_exhausted():
				try:
					response = self._tls_send(
						request,
						stream=stream,
						timeout=timeout,
						verify=verify,
						cert=cert,
						proxies=proxies,
					)

					return response

				except RequestException as error:
					retries = retries.increment(
						method=request.method, url=request.url, error=error
					)
					retries.sleep()

		except MaxRetryError as retry_error:
			raise retry_error.reason

	def _tls_send(self, request: PreparedRequest, stream=False, timeout=None, verify=True, cert=None, proxies=None) -> Response:
		"""Translates the `requests.PreparedRequest` into a TLSRequest, performs the request, and then
		translates the repsonse to a `requests.Response`, and if there is any exception, it is also
		translated into an appropiate `requests.exceptions.RequestException` subclass."""
		tls_connection = self._get_tls_connection(request.url, proxies)
		tls_request = {
			"method": request.method,
			"url": request.url,
			"headers": dict(request.headers),
			"verify": verify,
			"timeout": timeout,
			"proxies": dict(proxies),
			"body": request.body,
		}
		if request.method != "GET":
			content_type = request.headers.get("Content-Type", None)
			if content_type == "application/json":
				tls_request["json"] = json.loads(request.body.decode())
			else:
				tls_request["data"] = request.body
		if tls_request["headers"].get("Content-Length", None):
			del tls_request["headers"]["Content-Length"]
		response = tls_connection.send(tls_request)

		return response

	def _get_tls_connection(self, url, proxies=None):
		"""Returns a new TLS connection to handle the request to a given URL.

		Args:
			url (str): the URL of the request being sent.
			proxies (dict, optional): A Requests-style dictionary of proxies used on this request.

		Returns:
			TLSConnectionPool: a connection pool that is capable of handling the given request.
		"""
		proxy_url = select_proxy(url, proxies)

		if proxy_url:
			pool = self._pool_provider.get_pool_for_proxied_url(proxy_url, url)
		else:
			pool = self._pool_provider.get_pool_for_url(url)

		return pool

	def close(self):
		"""Cleans up adapter specific items."""
		self._pool_provider.clear()
