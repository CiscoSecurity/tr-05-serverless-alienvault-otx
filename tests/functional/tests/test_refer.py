import pytest
from urllib.parse import quote
from ctrlibrary.core.utils import get_observables
from ctrlibrary.threatresponse.enrich import enrich_refer_observables
from tests.functional.tests.constants import (
    MODULE_NAME,
    OBS_HUMAN_READABLE
)


@pytest.mark.parametrize(
    'observable_type, observable',
    (('ip', '54.38.157.11'),
     ('ipv6', '2620:12f:c000:0:92e2:baff:fecd:3f94'),
     ('url', 'http://blockchains.pk/nw_NIHbAj35.bin'),
     ('email', 'ysadmin@meraki.com'),
     ('domain', 'jsebnawkndwandawd.sh'),
     ('sha256',
      'af689a29dab28eedb5b2ee5bf0b94be2112d0881fad815fa082dc3b9d224fce0'),
     ('md5', 'f8290f2d593a05ea811edbd3bff6eacc'),
     ('sha1', 'da892cf09cf37a5f3aebed596652d209193c47eb'))
)
def test_positive_smoke_enrich_health(module_headers, observable,
                                      observable_type):
    """Perform testing for enrich health endpoint to check status of AlienVault
    OTX module

    ID: CCTRI-1336-6d0d5b40-6d1d-46a5-97f8-ff5f38defd5a

    Steps:
        1. Send request to enrich health endpoint

    Expectedresults:
        1. Check that data in response body contains status Ok from AlienVault
        OTX module

    Importance: Critical
    """
    observables = [{'type': observable_type, 'value': observable}]
    response_from_all_modules = enrich_refer_observables(
        payload=observables,
        **{'headers': module_headers}
    )['data']
    response_from_alien_vault = get_observables(response_from_all_modules,
                                                MODULE_NAME)
    assert response_from_alien_vault['module'] == MODULE_NAME
    assert response_from_alien_vault['module_instance_id']
    assert response_from_alien_vault['module_type_id']
    assert response_from_alien_vault['id'] == (
        f'ref-avotx-search-{observable_type}-{quote(observable, safe="")}')
    assert response_from_alien_vault['title'] == (
        f'Search for this {OBS_HUMAN_READABLE[observable_type]}')
    assert (response_from_alien_vault['description']) == (
        f'Lookup this {OBS_HUMAN_READABLE[observable_type]} on {MODULE_NAME}')
    assert response_from_alien_vault['categories'][0] == MODULE_NAME
    assert response_from_alien_vault['categories'][1] == 'Search'
