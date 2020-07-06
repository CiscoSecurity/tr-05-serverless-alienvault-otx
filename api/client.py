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

    def query(self, route, headers=None, params=None):
        response = requests.get(
            f"{self.url.rstrip('/')}/{route.lstrip('/')}",
            headers={**self.headers, **(headers or {})},
            params={**self.params, **(params or {})},
        )

        if response.status_code == HTTPStatus.FORBIDDEN:
            raise AuthenticationRequiredError

        if response.status_code != HTTPStatus.OK:
            response_reason_phrase = HTTPStatus(response.status_code).phrase
            raise RelayError(
                f'Reason: {response.status_code} {response_reason_phrase}'
            )

        return response.json()
