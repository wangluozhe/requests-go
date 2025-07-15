from .tls_client import Session
from .tls_config import TLSConfig


class TLSRequest:
	def __init__(self, tls_config=None):
		if tls_config:
			self._tls_config = tls_config
		if type(self._tls_config) == dict:
			self._tls_config = TLSConfig().fromJSON(self._tls_config)
		self._session = self._new_tls()

	def _new_tls(self) -> Session:
		session = Session(self._tls_config)
		return session

	def close(self) -> None:
		self._session = self._new_tls()

	def reset(self) -> None:
		self._session = self._new_tls()

	def send(self, options: dict = {}):
		response = self._session.request(**options)
		return response
