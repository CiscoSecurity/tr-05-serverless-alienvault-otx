import json
from os import cpu_count
from typing import Optional

from authlib.jose import jwt
from authlib.jose.errors import BadSignatureError, DecodeError
from flask import request, current_app, jsonify, g

from api.errors import (
    InvalidPayloadReceivedError,
    RelayError,
    AuthenticationRequiredError,
)


def get_auth_token():
    expected_errors = {
        KeyError: 'Authorization header is missing',
        AssertionError: 'Wrong authorization type'
    }
    try:
        scheme, token = request.headers['Authorization'].split()
        assert scheme.lower() == 'bearer'
        return token
    except tuple(expected_errors) as error:
        raise AuthenticationRequiredError(expected_errors[error.__class__])


def get_key() -> Optional[str]:
    expected_errors = {
        KeyError: 'Wrong JWT payload structure',
        TypeError: '<SECRET_KEY> is missing',
        BadSignatureError: 'Failed to decode JWT with provided key',
        DecodeError: 'Wrong JWT structure'
    }
    token = get_auth_token()
    try:
        return jwt.decode(token, current_app.config['SECRET_KEY'])["key"]
    except tuple(expected_errors) as error:
        raise AuthenticationRequiredError(expected_errors[error.__class__])


def get_json(schema):
    data = request.get_json(force=True, silent=True, cache=False)

    error = schema.validate(data)

    if error:
        reason = json.dumps(error)
        raise InvalidPayloadReceivedError(reason=reason)

    return data


def jsonify_data(data):
    return jsonify({'data': data})


def jsonify_errors(error: RelayError):
    payload = {'errors': [error.json()]}

    if 'bundle' in g:
        data = g.bundle.json()
        if data:
            payload['data'] = data

    return jsonify(payload)


def get_workers(iterable):
    return min((cpu_count() or 1) * 5, len(iterable)) or 1
