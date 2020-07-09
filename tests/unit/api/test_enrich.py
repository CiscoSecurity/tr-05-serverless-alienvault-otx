from http import HTTPStatus
from unittest import mock
from urllib.parse import quote

from authlib.jose import jwt
from pytest import fixture

from api.mappings import Sighting, Indicator, Relationship
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
            'value': 'jsebnawkndwandawd.sh',
        },
        {
            'type': 'email',
            'value': 'msalem@webalo.com',
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
    response = client.post(avotx_api_route,
                           json=valid_json,
                           headers=headers(invalid_jwt))

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


def avotx_api_response(status_code):
    mock_response = mock.MagicMock()

    mock_response.status_code = status_code

    if status_code == HTTPStatus.OK:
        payload = {
            'results': [
                {
                    'TLP': 'white',
                    'author': {
                        'username': 'JoriQ',
                    },
                    'description': (
                        'This is simply the best pulse '
                        'in the history of humankind!'
                    ),
                    'indicators': [
                        {
                            'indicator': 'jsebnawkndwandawd.sh',
                            'created': '1970-01-01T00:00:00',
                            'expiration': None,
                        },
                        {
                            'indicator': 'f8290f2d593a05ea811edbd3bff6eacc',
                            'created': '1970-01-02T00:00:00',
                            'expiration': None,
                        },
                        {
                            'indicator': (
                                'da892cf09cf37a5f3aebed596652d209193c47eb'
                            ),
                            'created': '1970-01-03T00:00:00',
                            'expiration': None,
                        },
                        {
                            'indicator': (
                                'af689a29dab28eedb5b2ee5bf0b94be2'
                                '112d0881fad815fa082dc3b9d224fce0'
                            ),
                            'created': '1970-01-04T00:00:00',
                            'expiration': None,
                        },
                        {
                            'indicator': '54.38.157.11',
                            'created': '1970-01-05T00:00:00',
                            'expiration': '1970-01-06T00:00:00',
                        },
                    ],
                    'id': 'q1w2e3r4t5y6',
                    'name': 'Best Pulse Ever',
                    'tags': ['open', 'threat', 'exchange'],
                },
            ],
        }

        mock_response.json = lambda: payload

    return mock_response


@fixture(scope='module')
def expected_payload(any_route, client, valid_json):
    app = client.application

    payload = None

    if any_route.startswith('/deliberate'):
        payload = {}

    if any_route.startswith('/observe'):
        observable_types = {'domain', 'md5', 'sha1', 'sha256', 'ip'}

        observables = [
            observable
            for observable in valid_json
            if observable['type'] in observable_types
        ]

        count = len(observables)

        start_times = [
            f'1970-01-0{day}T00:00:00Z'
            for day in range(1, count + 1)
        ]

        observed_times = [
            {'start_time': start_time}
            for start_time in start_times
        ]

        for observed_time in observed_times:
            observed_time['end_time'] = observed_time['start_time']

        valid_times = [
            {'start_time': start_time}
            for start_time in start_times
        ]

        valid_times[-1]['end_time'] = f'1970-01-0{count + 1}T00:00:00Z'

        description = (
            'This is simply the best pulse in the history of humankind!'
        )
        external_ids = ['q1w2e3r4t5y6']
        producer = 'JoriQ'
        short_description = description
        source_uri = (
            f"{app.config['AVOTX_URL'].rstrip('/')}/pulse/{external_ids[0]}"
        )
        tags = ['open', 'threat', 'exchange']
        title = 'Best Pulse Ever'
        tlp = 'white'

        # Implement a dummy class initializing its instances
        # only after the first comparison with any other object.
        class LazyEqualizer:
            NONE = object()

            def __init__(self):
                self.value = self.NONE

            def __eq__(self, other):
                if self.value is self.NONE:
                    self.value = other

                return self.value == other

        sighting_refs = [LazyEqualizer() for _ in range(count)]
        indicator_refs = [LazyEqualizer() for _ in range(count)]

        payload = {
            'sightings': {
                'count': count,
                'docs': [
                    {
                        'description': description,
                        'external_ids': external_ids,
                        'id': sighting_ref,
                        'observables': [observable],
                        'observed_time': observed_time,
                        'source_uri': source_uri,
                        'title': title,
                        'tlp': tlp,
                        **Sighting.DEFAULTS
                    }
                    for sighting_ref, observable, observed_time
                    in zip(sighting_refs, observables, observed_times)
                ],
            },
            'indicators': {
                'count': count,
                'docs': [
                    {
                        'id': indicator_ref,
                        'external_ids': external_ids,
                        'producer': producer,
                        'short_description': short_description,
                        'source_uri': source_uri,
                        'tags': tags,
                        'title': title,
                        'tlp': tlp,
                        'valid_time': valid_time,
                        **Indicator.DEFAULTS
                    }
                    for indicator_ref, observable, valid_time
                    in zip(indicator_refs, observables, valid_times)
                ],
            },
            'relationships': {
                'count': count,
                'docs': [
                    {
                        'id': mock.ANY,
                        'source_ref': sighting_ref,
                        'target_ref': indicator_ref,
                        **Relationship.DEFAULTS
                    }
                    for sighting_ref, indicator_ref
                    in zip(sighting_refs, indicator_refs)
                ],
            },
        }

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
                    f"{observable['category']}/"
                    f"{quote(observable['value'], safe='@:')}"
                ),
                'categories': ['Search', 'AlienVault OTX'],
            }

            payload.append(reference)

    assert payload is not None, f'Unknown route: {any_route}.'

    return {'data': payload}


def test_enrich_call_success(any_route,
                             client,
                             valid_json,
                             avotx_api_request,
                             valid_jwt,
                             expected_payload):
    app = client.application

    response = None

    if any_route.startswith('/deliberate'):
        response = client.post(any_route)

    if any_route.startswith('/observe'):
        avotx_api_request.return_value = avotx_api_response(HTTPStatus.OK)

        response = client.post(any_route,
                               json=valid_json,
                               headers=headers(valid_jwt))

        expected_url = f"{app.config['AVOTX_URL']}/api/v1/search/pulses"

        expected_headers = {
            'User-Agent': app.config['CTR_USER_AGENT'],
            'X-OTX-API-KEY': (
                jwt.decode(valid_jwt, app.config['SECRET_KEY'])['key']
            ),
        }

        observable_types = {'domain', 'md5', 'sha1', 'sha256', 'ip'}

        expected_params_list = [
            {
                'limit': app.config['CTR_ENTITIES_LIMIT'],
                'sort': '-created',
                'q': observable['value'],
            }
            for observable in valid_json
            if observable['type'] in observable_types
        ]

        avotx_api_request.assert_has_calls([
            mock.call(expected_url,
                      headers=expected_headers,
                      params=expected_params)
            for expected_params in expected_params_list
        ])

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
    for status_code, error_code, error_message in [
        (
            HTTPStatus.FORBIDDEN,
            'authentication required',
            'Authentication required.',
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

        avotx_api_request.return_value = avotx_api_response(status_code)

        response = client.post(avotx_api_route,
                               json=valid_json,
                               headers=headers(valid_jwt))

        expected_url = f"{app.config['AVOTX_URL']}/api/v1/search/pulses"

        expected_headers = {
            'User-Agent': app.config['CTR_USER_AGENT'],
            'X-OTX-API-KEY': (
                jwt.decode(valid_jwt, app.config['SECRET_KEY'])['key']
            ),
        }

        observable_types = {'domain', 'md5', 'sha1', 'sha256', 'ip'}

        expected_params = {
            'limit': app.config['CTR_ENTITIES_LIMIT'],
            'sort': '-created',
            'q': next(
                observable['value']
                for observable in valid_json
                if observable['type'] in observable_types
            ),
        }

        avotx_api_request.assert_called_once_with(expected_url,
                                                  headers=expected_headers,
                                                  params=expected_params)

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
