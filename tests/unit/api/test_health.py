from http import HTTPStatus
from unittest import mock

from authlib.jose import jwt
from pytest import fixture

from .utils import headers


def routes():
    yield '/health'


@fixture(scope='module', params=routes(), ids=lambda route: f'POST {route}')
def route(request):
    return request.param


def test_health_call_with_invalid_jwt_failure(route, client, invalid_jwt):
    response = client.post(route, headers=headers(invalid_jwt))

    expected_payload = {
        'errors': [
            {
                'code': 'authentication required',
                'message': 'Authentication required.',
                'type': 'fatal',
            }
        ]
    }

    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == expected_payload


@fixture(scope='function')
def avotx_api_request():
    with mock.patch('requests.get') as mock_request:
        yield mock_request


def avotx_api_response(status_code):
    mock_response = mock.MagicMock()

    mock_response.status_code = status_code

    return mock_response


def test_health_call_success(route, client, avotx_api_request, valid_jwt):
    app = client.application

    avotx_api_request.return_value = avotx_api_response(HTTPStatus.OK)

    response = client.post(route, headers=headers(valid_jwt))

    expected_url = f"{app.config['AVOTX_URL']}/api/v1/user/me"

    expected_headers = {
        'User-Agent': app.config['CTR_USER_AGENT'],
        'X-OTX-API-KEY': (
            jwt.decode(valid_jwt, app.config['SECRET_KEY'])['key']
        ),
    }

    avotx_api_request.assert_called_once_with(expected_url,
                                              headers=expected_headers,
                                              params=None)

    expected_payload = {'data': {'status': 'ok'}}

    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == expected_payload


def test_health_call_with_external_error_from_avotx_failure(route,
                                                            client,
                                                            avotx_api_request,
                                                            valid_jwt):
    for status_code, error_code, error_message in [
        (
            HTTPStatus.FORBIDDEN,
            'authentication required',
            'Authentication required.',
        ),
        (
            HTTPStatus.INTERNAL_SERVER_ERROR,
            'oops',
            'Something went wrong.',
        ),
    ]:
        app = client.application

        avotx_api_request.return_value = avotx_api_response(status_code)

        response = client.post(route, headers=headers(valid_jwt))

        expected_url = f"{app.config['AVOTX_URL']}/api/v1/user/me"

        expected_headers = {
            'User-Agent': app.config['CTR_USER_AGENT'],
            'X-OTX-API-KEY': (
                jwt.decode(valid_jwt, app.config['SECRET_KEY'])['key']
            ),
        }

        avotx_api_request.assert_called_once_with(expected_url,
                                                  headers=expected_headers,
                                                  params=None)

        avotx_api_request.reset_mock()

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
