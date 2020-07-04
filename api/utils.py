import json
from typing import Optional

from authlib.jose import jwt
from authlib.jose.errors import JoseError
from flask import request, current_app, jsonify, g

from api.errors import InvalidPayloadReceivedError, RelayError


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


def jsonify_data(data):
    return jsonify({'data': data})


def jsonify_errors(error: RelayError):
    payload = {'errors': [error.json()]}

    if 'bundle' in g:
        data = g.bundle.json()
        if data:
            payload['data'] = data

    return jsonify(payload)
