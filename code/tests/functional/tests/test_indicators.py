import pytest
from ctrlibrary.core.utils import get_observables
from ctrlibrary.threatresponse.enrich import enrich_observe_observables
from tests.functional.tests.constants import (
    MODULE_NAME,
    ALIEN_VAULT_URL,
    CONFIDENCE_LEVEL,
    INTEGRATION_NAME
)


@pytest.mark.parametrize(
    'observable_type, observable',
    (('ip', '99.85.80.169'),
     ('ipv6', '2001:14ba:1f00:0:1117:e76e:843d:f803'),
     ('url', 'http://blockchains.pk/nw_NIHbAj35.bin'),
     ('domain', 'jsebnawkndwandawd.sh'),
     ('sha256',
      'efdd3ee0f816eba8ab1cba3643e42b40aaa16654d5120c67169d1b002e7f714d'),
     ('md5', 'd8414d743778cae103c15461200ec64d'),
     ('sha1', '4f79d1a01b9b5cb3cb65a9911db2a02ea3bb7c45'))
)
def test_positive_smoke_enrich_indicators(module_headers, observable,
                                          observable_type):
    """Perform testing for enrich observe observable endpoint to check
    indicators of AlienVault OTX module

    ID: CCTRI-1334-bcef4d6e-c1df-11ea-b3de-0242ac130004

    Steps:
        1. Send request to enrich observe observable endpoint

    Expectedresults:
        1. Response body contains indicators entity with needed fields from
        AlienVault OTX module

    Importance: Critical
    """
    observables = [{'type': observable_type, 'value': observable}]
    response_from_all_modules = enrich_observe_observables(
        payload=observables,
        **{'headers': module_headers}
    )
    response_from_alien_vault = get_observables(response_from_all_modules,
                                                MODULE_NAME)
    assert response_from_alien_vault['module'] == MODULE_NAME
    assert response_from_alien_vault['module_instance_id']
    assert response_from_alien_vault['module_type_id']

    indicators = response_from_alien_vault['data']['indicators']

    assert len(indicators['docs']) > 0

    for indicator in indicators['docs']:
        assert 'tags' in indicator
        assert indicator['valid_time']['start_time']
        assert indicator['producer']
        assert indicator['schema_version']
        assert indicator['type'] == 'indicator'
        assert indicator['source'] == INTEGRATION_NAME
        assert indicator['external_ids']
        assert 'short_description' in indicator
        assert indicator['title']
        assert indicator['source_uri'] == (
            f'{ALIEN_VAULT_URL}/pulse/{indicator["external_ids"][0]}')
        assert indicator['id'].startswith('transient:indicator')
        assert indicator['tlp']
        assert indicator['confidence'] == CONFIDENCE_LEVEL

    assert indicators['count'] == len(indicators['docs'])
