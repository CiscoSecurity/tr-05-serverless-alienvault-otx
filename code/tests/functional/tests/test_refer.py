import pytest
from urllib.parse import quote
from ctrlibrary.core.utils import get_observables
from ctrlibrary.threatresponse.enrich import enrich_refer_observables
from tests.functional.tests.constants import (
    MODULE_NAME,
    OBSERVABLE_HUMAN_READABLE_NAME,
    INTEGRATION_NAME
)


@pytest.mark.parametrize(
    'observable_type, observable',
    (('ip', '99.85.80.169'),
     ('ipv6', '2001:14ba:1f00:0:1117:e76e:843d:f803'),
     ('url', 'http://blockchains.pk/nw_NIHbAj35.bin'),
     ('email', 'msalem@webalo.com'),
     ('domain', 'jsebnawkndwandawd.sh'),
     ('sha256',
      'efdd3ee0f816eba8ab1cba3643e42b40aaa16654d5120c67169d1b002e7f714d'),
     ('md5', 'd8414d743778cae103c15461200ec64d'),
     ('sha1', '4f79d1a01b9b5cb3cb65a9911db2a02ea3bb7c45'))
)
def test_positive_smoke_enrich_refer_observables(module_headers, observable,
                                                 observable_type):
    """Perform testing for enrich refer observable endpoint to check status of
    AlienVault OTX module

    ID: CCTRI-1336-1f700099-447c-4803-9df7-d1c97cc5abdb

    Steps:
        1. Send request to enrich refer observable endpoint

    Expectedresults:
        1. Response body contains refer entity with needed fields from
        AlienVault OTX module

    Importance: Critical
    """
    observables = [{'type': observable_type, 'value': observable}]
    response_from_all_modules = enrich_refer_observables(
        payload=observables,
        **{'headers': module_headers}
    )
    response_from_alien_vault = get_observables(response_from_all_modules,
                                                MODULE_NAME)
    assert response_from_alien_vault['module'] == MODULE_NAME
    assert response_from_alien_vault['module_instance_id']
    assert response_from_alien_vault['module_type_id']
    assert response_from_alien_vault['id'] == (
        f'ref-avotx-search-{observable_type}-{quote(observable, safe="")}')
    assert response_from_alien_vault['title'] == (
        f'Search for this {OBSERVABLE_HUMAN_READABLE_NAME[observable_type]}')
    assert (response_from_alien_vault['description']) == (
        f'Lookup this {OBSERVABLE_HUMAN_READABLE_NAME[observable_type]} on '
        f'{INTEGRATION_NAME}')
    assert response_from_alien_vault['categories'] == [INTEGRATION_NAME, 'Search']
