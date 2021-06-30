from unittest.mock import MagicMock, patch

import jwt
from app import app
from pytest import fixture
from tests.unit.mock_for_tests import (
    PRIVATE_KEY, EXPECTED_RESPONSE_OF_JWKS_ENDPOINT,
    RESPONSE_OF_JWKS_ENDPOINT_WITH_WRONG_KEY
)


@fixture(scope='session')
def client():
    app.rsa_private_key = PRIVATE_KEY

    app.testing = True

    with app.test_client() as client:
        yield client


@fixture(scope='function')
def mock_request():
    with patch('requests.get') as mock_request:
        yield mock_request


@fixture(scope='session')
def valid_jwt(client):
    def _make_jwt(
            key='test',
            jwks_host='visibility.amp.cisco.com',
            aud='http://localhost',
            limit=100,
            kid='02B1174234C29F8EFB69911438F597FF3FFEE6B7',
            wrong_structure=False,
            wrong_jwks_host=False
    ):
        payload = {
            'key': key,
            'jwks_host': jwks_host,
            'aud': aud,
            'CTR_ENTITIES_LIMIT': limit
        }

        if wrong_jwks_host:
            payload.pop('jwks_host')

        if wrong_structure:
            payload.pop('key')

        return jwt.encode(
            payload, client.application.rsa_private_key, algorithm='RS256',
            headers={
                'kid': kid
            }
        )

    return _make_jwt


@fixture(scope='session')
def get_public_key():
    mock_response = MagicMock()
    payload = EXPECTED_RESPONSE_OF_JWKS_ENDPOINT
    mock_response.json = lambda: payload
    return mock_response


@fixture(scope='session')
def get_wrong_public_key():
    mock_response = MagicMock()
    payload = RESPONSE_OF_JWKS_ENDPOINT_WITH_WRONG_KEY
    mock_response.json = lambda: payload
    return mock_response


@fixture(scope='module')
def valid_json():
    return [
        {
            'type': 'device',
            'value': 'laptop',
        },
        {
            'type': 'domain',
            'value': 'jsebnawkndwandawd.sh',
        },
        {
            'type': 'email',
            'value': 'msalem@webalo.com',
        },
        {
            'type': 'md5',
            'value': 'd8414d743778cae103c15461200ec64d',
        },
        {
            'type': 'sha1',
            'value': '4f79d1a01b9b5cb3cb65a9911db2a02ea3bb7c45',
        },
        {
            'type': 'sha256',
            'value': 'efdd3ee0f816eba8ab1cba3643e42b40aaa16654d5120c67169d1b002e7f714d',  # noqa: E501
        },
        {
            'type': 'ip',
            'value': '99.85.80.169',
        },
        {
            'type': 'ipv6',
            'value': '2001:14ba:1f00:0:1117:e76e:843d:f803',
        },
        {
            'type': 'url',
            'value': 'http://blockchains.pk/nw_NIHbAj35.bin',
        },
        {
            'type': 'user',
            'value': 'admin',
        },
    ]
