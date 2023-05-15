from itertools import chain
from urllib3.poolmanager import PoolManager
from urllib3.util import parse_url
from requests.utils import prepend_scheme_if_needed
from requests.exceptions import InvalidProxyURL

from .pool import TLSHandlerPool, ProxyTLSHandlerPool


class TLSPoolProvider(object):
	"""This class provides a pool for a given URL. The pool then will handle all
	connections for that specific URL."""

	def __init__(self, max_pools, max_pool_size, pool_block, tls_config):
		self._max_pools = max_pools
		self._max_pool_size = max_pool_size
		self._pool_block = pool_block
		self._tls_config = tls_config

		self._pool_manager = self._create_pool_manager(self._pool_factory)

		self._pool_manager_per_proxy = {}

	def _pool_factory(self, url, port, **kwargs):
		kwargs["tls_config"] = self._tls_config
		return TLSHandlerPool(**kwargs)

	def _create_pool_manager(self, pool_factory):
		pool_manager = PoolManager(
			num_pools=self._max_pools,
			maxsize=self._max_pool_size,
			block=self._pool_block,
			strict=True,
		)

		pool_manager.pool_classes_by_scheme = {
			"http": pool_factory,
			"https": pool_factory,
		}

		return pool_manager

	def get_pool_for_url(self, url):
		"""Returns an instance of a TLSHandlerPool for a given URL"""
		return self._pool_manager.connection_from_url(url)

	def get_pool_for_proxied_url(self, proxy_url, url):
		"""Returns an instance of a TLSHandlerPool for a given URL, but using a Proxy"""
		parsed_proxy_url = _parse_proxy_url(proxy_url)

		if parsed_proxy_url not in self._pool_manager_per_proxy:
			# Create here the poolmanager for proxy
			self._pool_manager_per_proxy[parsed_proxy_url] = self._create_pool_manager(
				lambda url, port, maxsize=1, **kwargs: ProxyTLSHandlerPool(
					parsed_proxy_url, maxsize=maxsize, tls_config=self._tls_config, **kwargs
				)
			)

		pool_manager = self._pool_manager_per_proxy[parsed_proxy_url]

		return pool_manager.connection_from_url(url)

	@property
	def _pool_managers(self):
		return chain((self._pool_manager,), self._pool_manager_per_proxy.values())

	def clear(self):
		for pool_manager in self._pool_managers:
			pool_manager.clear()

	def __len__(self):
		"""Returns the number of pools that this provider currently handles"""
		proxy_pools_count = sum(
			len(pool_manager.pools) for pool_manager in self._pool_managers
		)
		return proxy_pools_count


def _parse_proxy_url(proxy_url):
	proxy_url = prepend_scheme_if_needed(proxy_url, "http")
	parsed_proxy_url = parse_url(proxy_url)

	if not parsed_proxy_url.host:
		raise InvalidProxyURL(
			"Please check proxy URL. It is malformed" " and could be missing the host."
		)

	return parsed_proxy_url
