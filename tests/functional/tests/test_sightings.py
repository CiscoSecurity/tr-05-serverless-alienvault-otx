import pytest
from ctrlibrary.core.utils import get_observables
from ctrlibrary.threatresponse.enrich import enrich_observe_observables
from tests.functional.tests.constants import (
    MODULE_NAME,
    ALIEN_VAULT_URL,
    CONFIDENCE_LEVEL
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
def test_positive_smoke_enrich_sightings(module_headers, observable,
                                         observable_type):
    """Perform testing for enrich observe observable endpoint to check
    sightings of AlienVault OTX module

    ID: CCTRI-1333-027027d6-bdd9-4c03-8704-65a541f8b7ee

    Steps:
        1. Send request to enrich observe observable endpoint

    Expectedresults:
        1. Response body contains sighting entity with needed fields from
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

    sightings = response_from_alien_vault['data']['sightings']

    assert len(sightings['docs']) > 0

    for sighting in sightings['docs']:
        assert 'description' in sighting
        assert sighting['schema_version']
        assert sighting['observables'] == observables
        assert sighting['type'] == 'sighting'
        assert sighting['source'] == MODULE_NAME
        assert sighting['external_ids']
        assert sighting['title']
        assert sighting['internal'] is False
        assert sighting['source_uri'] == (
            f'{ALIEN_VAULT_URL}/pulse/{sighting["external_ids"][0]}')
        assert sighting['id'].startswith('transient:sighting')
        assert sighting['count'] == 1
        assert sighting['tlp']
        assert sighting['confidence'] == CONFIDENCE_LEVEL
        assert sighting['observed_time']['start_time'] == (
            sighting['observed_time']['end_time'])

    assert sightings['count'] == len(sightings['docs'])
