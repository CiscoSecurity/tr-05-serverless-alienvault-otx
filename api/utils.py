import json
from http import HTTPStatus
from typing import Optional

import requests
from authlib.jose import jwt
from authlib.jose.errors import JoseError
from flask import request, current_app, jsonify

from api.errors import (
    InvalidPayloadReceivedError,
    AuthenticationRequiredError,
    RelayError,
)


def get_jwt():
    try:
        scheme, token = request.headers['Authorization'].split()
        assert scheme.lower() == 'bearer'
        return jwt.decode(token, current_app.config['SECRET_KEY'])
    except (KeyError, ValueError, AssertionError, JoseError):
        return {}


def get_key() -> Optional[str]:
    return get_jwt().get('key')  # AVOTX_API_KEY


def get_json(schema):
    data = request.get_json(force=True, silent=True, cache=False)

    error = schema.validate(data)

    if error:
        raise InvalidPayloadReceivedError(json.dumps(error))

    return data


def query_api(route, params=None):
    key = get_key()

    if key is None:
        raise AuthenticationRequiredError

    url = f"{current_app.config['AVOTX_URL']}/api/v1/{route}"

    headers = {
        'User-Agent': current_app.config['CTR_USER_AGENT'],
        'X-OTX-API-KEY': key,
    }

    response = requests.get(url, headers=headers, params=params)

    if response.status_code == HTTPStatus.FORBIDDEN:
        raise AuthenticationRequiredError

    if response.status_code != HTTPStatus.OK:
        raise RelayError

    return response.json()


def jsonify_data(data):
    return jsonify({'data': data})


def jsonify_errors(error):
    return jsonify({'errors': [error.json()]})
