from http import HTTPStatus
from unittest import mock
from urllib.parse import quote

from pytest import fixture

from .utils import headers


def implemented_routes():
    yield '/observe/observables'
    yield '/refer/observables'


@fixture(scope='module',
         params=implemented_routes(),
         ids=lambda route: f'POST {route}')
def implemented_route(request):
    return request.param


@fixture(scope='module')
def invalid_json():
    return [{'type': 'unknown', 'value': ''}]


def test_enrich_call_with_invalid_json_failure(implemented_route,
                                               client,
                                               invalid_json):
    response = client.post(implemented_route, json=invalid_json)

    # The actual error message is quite unwieldy, so let's just ignore it.
    expected_payload = {
        'errors': [
            {
                'code': 'invalid payload received',
                'message': mock.ANY,
                'type': 'fatal',
            }
        ]
    }

    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == expected_payload


def avotx_api_routes():
    yield '/observe/observables'


@fixture(scope='module',
         params=avotx_api_routes(),
         ids=lambda route: f'POST {route}')
def avotx_api_route(request):
    return request.param


@fixture(scope='module')
def valid_json():
    return [
        {
            'type': 'device',
            'value': 'laptop',
        },
        {
            'type': 'domain',
            'value': 'tldrnet.top',
        },
        {
            'type': 'email',
            'value': 'ysadmin@meraki.com',
        },
        {
            'type': 'md5',
            'value': 'f8290f2d593a05ea811edbd3bff6eacc',
        },
        {
            'type': 'sha1',
            'value': 'da892cf09cf37a5f3aebed596652d209193c47eb',
        },
        {
            'type': 'sha256',
            'value': (
                'af689a29dab28eedb5b2ee5bf0b94be2112d0881fad815fa082dc3b9d224fce0'  # noqa: E501
            ),
        },
        {
            'type': 'ip',
            'value': '54.38.157.11',
        },
        {
            'type': 'ipv6',
            'value': '2620:12f:c000:0:92e2:baff:fecd:3f94',
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


def test_enrich_call_with_valid_json_but_invalid_jwt_failure(avotx_api_route,
                                                             client,
                                                             valid_json,
                                                             invalid_jwt):
    pass
    # TODO: implement after /observe/observables


def all_routes():
    yield '/deliberate/observables'
    yield '/observe/observables'
    yield '/refer/observables'


@fixture(scope='module',
         params=all_routes(),
         ids=lambda route: f'POST {route}')
def any_route(request):
    return request.param


@fixture(scope='function')
def avotx_api_request():
    with mock.patch('requests.get') as mock_request:
        yield mock_request


def avotx_api_response():
    pass
    # TODO: implement after /observe/observables


@fixture(scope='module')
def expected_payload(any_route, client, valid_json):
    app = client.application

    payload = None

    if any_route.startswith('/deliberate'):
        payload = {}

    if any_route.startswith('/observe'):
        payload = {}

    if any_route.startswith('/refer'):
        observable_types = {
            'domain': {'name': 'domain', 'category': 'domain'},
            'email': {'name': 'email', 'category': 'email'},
            'md5': {'name': 'MD5', 'category': 'file'},
            'sha1': {'name': 'SHA1', 'category': 'file'},
            'sha256': {'name': 'SHA256', 'category': 'file'},
            'ip': {'name': 'IP', 'category': 'ip'},
            'ipv6': {'name': 'IPv6', 'category': 'ip'},
            'url': {'name': 'URL', 'category': 'url'},
        }

        payload = []

        for observable in valid_json:
            if observable['type'] not in observable_types:
                continue

            observable = {**observable, **observable_types[observable['type']]}

            reference = {
                'id': (
                    f"ref-avotx-search-{observable['type']}-"
                    f"{quote(observable['value'], safe='')}"
                ),
                'title': f"Search for this {observable['name']}",
                'description': (
                    f"Lookup this {observable['name']} on AlienVault OTX"
                ),
                'url': (
                    f"{app.config['AVOTX_URL']}/indicator/"
                    f"{observable['category']}/{observable['value']}"
                ),
                'categories': ['Search', 'AlienVault OTX'],
            }

            payload.append(reference)

    assert payload is not None, f'Unknown route: {any_route}.'

    return {'data': payload}


def test_enrich_call_success(any_route,
                             client,
                             valid_json,
                             valid_jwt,
                             expected_payload):
    # app = client.application

    response = None

    if any_route.startswith('/deliberate'):
        response = client.post(any_route)

    if any_route.startswith('/observe'):
        response = client.post(any_route,
                               json=valid_json,
                               headers=headers(valid_jwt))

    if any_route.startswith('/refer'):
        response = client.post(any_route, json=valid_json)

    assert response is not None, f'Unknown route: {any_route}.'

    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == expected_payload


def test_enrich_call_with_external_error_from_avotx_failure(avotx_api_route,
                                                            client,
                                                            valid_json,
                                                            avotx_api_request,
                                                            valid_jwt):
    pass
    # TODO: implement after /observe/observables
