from requests import Response
from .tls_client.response import Response as TLSResponse


def build_response(tls_response: TLSResponse) -> Response:
	response = Response()
	response.url = tls_response.url
	response.headers = tls_response.headers
	response.cookies = tls_response.cookies
	response.status_code = tls_response.status_code
	response._content = tls_response.content
	return response
