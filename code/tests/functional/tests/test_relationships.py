import pytest
from ctrlibrary.core.utils import get_observables
from ctrlibrary.threatresponse.enrich import enrich_observe_observables
from tests.functional.tests.constants import MODULE_NAME


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
def test_positive_smoke_enrich_relationships(module_headers, observable,
                                             observable_type):
    """Perform testing for enrich observe observable endpoint to check
    relationships of AlienVault OTX module

    ID: CCTRI-1335-943cacc5-0157-42d8-af5c-3778c4b79031

    Steps:
        1. Send request to enrich observe observable endpoint

    Expectedresults:
        1. Response body contains relationships entity with needed fields from
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

    relationships = response_from_alien_vault['data']['relationships']

    indicators_ids = {
        indicator['id'] for indicator
        in response_from_alien_vault['data']['indicators']['docs']
    }
    sightings_ids = {
        sighting['id'] for sighting
        in response_from_alien_vault['data']['sightings']['docs']
    }
    target_ref = {
        relationship['target_ref'] for relationship
        in response_from_alien_vault['data']['relationships']['docs']
    }
    source_ref = {
        relationship['source_ref'] for relationship
        in response_from_alien_vault['data']['relationships']['docs']
    }

    assert target_ref == indicators_ids
    assert source_ref == sightings_ids

    assert len(relationships['docs']) > 0

    for relationship in relationships['docs']:
        assert relationship['schema_version']
        assert relationship['type'] == 'relationship'
        assert relationship['id'].startswith('transient:relationship')
        assert relationship['relationship_type'] == 'member-of'

    assert relationships['count'] == len(relationships['docs'])
