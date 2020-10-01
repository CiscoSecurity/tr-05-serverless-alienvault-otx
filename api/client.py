from http import HTTPStatus
from ssl import SSLCertVerificationError

import requests
from requests.exceptions import SSLError

from api.errors import (
    SSLCertificateVerificationFailedError,
    AuthenticationRequiredError,
    RelayError,
)


class Client:

    def __init__(self, key, url, headers=None, params=None):
        self.key = key
        self.url = url

        self.headers = headers or {}
        self.params = params or {}

        self.headers['X-OTX-API-KEY'] = self.key

    def query(self, endpoint, headers=None, params=None):
        try:
            response = requests.get(
                f"{self.url.rstrip('/')}/{endpoint.lstrip('/')}",
                headers={**self.headers, **(headers or {})},
                params={**self.params, **(params or {})},
            )
        except SSLError as error:
            # Go through a few layers of wrapped exceptions.
            error = error.args[0].reason.args[0]
            # Assume that a certificate could not be verified.
            assert isinstance(error, SSLCertVerificationError)
            reason = (
                getattr(error, 'verify_message', error.args[0]).capitalize()
            )
            raise SSLCertificateVerificationFailedError(reason=reason)

        if response.status_code == HTTPStatus.BAD_REQUEST:
            return None

        if response.status_code == HTTPStatus.FORBIDDEN:
            raise AuthenticationRequiredError(
                reason="Authorization failed on <3rd party name> side"
            )

        if response.status_code == HTTPStatus.NOT_FOUND:
            return None

        if response.status_code != HTTPStatus.OK:
            response_reason_phrase = HTTPStatus(response.status_code).phrase
            reason = f'Reason: {response.status_code} {response_reason_phrase}'
            raise RelayError(reason=reason)

        return response.json()
