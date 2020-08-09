from http import HTTPStatus

import requests

from api.errors import AuthenticationRequiredError, RelayError


class Client:

    def __init__(self, key, url, headers=None, params=None):
        self.key = key
        self.url = url

        self.headers = headers or {}
        self.params = params or {}

        self.headers['X-OTX-API-KEY'] = self.key

    def query(self, endpoint, headers=None, params=None):
        response = requests.get(
            f"{self.url.rstrip('/')}/{endpoint.lstrip('/')}",
            headers={**self.headers, **(headers or {})},
            params={**self.params, **(params or {})},
        )

        if response.status_code == HTTPStatus.BAD_REQUEST:
            return None

        if response.status_code == HTTPStatus.FORBIDDEN:
            raise AuthenticationRequiredError

        if response.status_code == HTTPStatus.NOT_FOUND:
            return None

        if response.status_code != HTTPStatus.OK:
            response_reason_phrase = HTTPStatus(response.status_code).phrase
            raise RelayError(
                f'Reason: {response.status_code} {response_reason_phrase}'
            )

        return response.json()
