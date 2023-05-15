from tls_client import Session

from .tls_config.config import random_tls_config
from .response import build_response


class TLSRequest:
	def __init__(self, tls_config=None):
		if tls_config:
			self._tls_config = tls_config
		else:
			self._tls_config = random_tls_config()
		if type(self._tls_config) != dict:
			self._tls_config = self._tls_config.toJSON()
		self._session = self._new_tls()

	def _new_tls(self) -> Session:
		session = Session(**self._tls_config)
		return session

	def close(self) -> None:
		self._session = self._new_tls()

	def reset(self) -> None:
		self._session = self._new_tls()

	def send(self, options: dict = {}):
		response = self._session.execute_request(**options)
		tls_response = build_response(response)
		return tls_response
