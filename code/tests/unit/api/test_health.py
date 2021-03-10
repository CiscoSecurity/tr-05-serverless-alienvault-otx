from http import HTTPStatus
from unittest import mock

import jwt
from pytest import fixture

from .utils import headers


def routes():
    yield '/health'


@fixture(scope='module', params=routes(), ids=lambda route: f'POST {route}')
def route(request):
    return request.param


@fixture(scope='function')
def mock_request():
    with mock.patch('requests.get') as mock_request:
        yield mock_request


def avotx_api_response(status_code):
    mock_response = mock.MagicMock()

    mock_response.status_code = status_code

    return mock_response


def test_health_call_success(
        route, client, mock_request, valid_jwt, get_public_key
):
    app = client.application

    mock_request.side_effect = [
        get_public_key, avotx_api_response(HTTPStatus.OK)
    ]

    response = client.post(route, headers=headers(valid_jwt()))

    expected_url = f"{app.config['AVOTX_URL']}/api/v1/user/me"

    expected_headers = {
        'User-Agent': app.config['CTR_USER_AGENT'],
        'X-OTX-API-KEY': (
            jwt.decode(valid_jwt(), options={'verify_signature': False})['key']
        ),
    }

    expected_params = {}

    mock_request.assert_called_with(expected_url,
                                    headers=expected_headers,
                                    params=expected_params)

    expected_payload = {'data': {'status': 'ok'}}

    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == expected_payload


def test_health_call_with_external_error_from_avotx_failure(route,
                                                            client,
                                                            mock_request,
                                                            valid_jwt,
                                                            get_public_key):
    for status_code, error_code, error_message in [
        (
            HTTPStatus.FORBIDDEN,
            'authorization error',
            ('Authorization failed: '
             'Authorization failed on AlienVault OTX side'),
        ),
        (
            HTTPStatus.INTERNAL_SERVER_ERROR,
            'oops',
            'Something went wrong. Reason: '
            f'{HTTPStatus.INTERNAL_SERVER_ERROR.value} '
            f'{HTTPStatus.INTERNAL_SERVER_ERROR.phrase}.',
        ),
    ]:
        app = client.application

        mock_request.side_effect = [
            get_public_key, avotx_api_response(status_code)
        ]

        response = client.post(route, headers=headers(valid_jwt()))

        expected_url = f"{app.config['AVOTX_URL']}/api/v1/user/me"

        expected_headers = {
            'User-Agent': app.config['CTR_USER_AGENT'],
            'X-OTX-API-KEY': (
                jwt.decode(
                    valid_jwt(), options={'verify_signature': False}
                )['key']
            ),
        }

        expected_params = {}

        mock_request.assert_called_with(expected_url,
                                        headers=expected_headers,
                                        params=expected_params)

        mock_request.reset_mock()

        expected_payload = {
            'errors': [
                {
                    'code': error_code,
                    'message': error_message,
                    'type': 'fatal',
                }
            ]
        }

        assert response.status_code == HTTPStatus.OK
        assert response.get_json() == expected_payload
