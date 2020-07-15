import pytest
from ctrlibrary.core.utils import get_observables
from ctrlibrary.threatresponse.enrich import enrich_observe_observables
from tests.functional.tests.constants import MODULE_NAME


@pytest.mark.parametrize(
    'observable_type, observable',
    (('ip', '54.38.157.11'),
     ('domain', 'jsebnawkndwandawd.sh'),
     ('sha256',
      'af689a29dab28eedb5b2ee5bf0b94be2112d0881fad815fa082dc3b9d224fce0'),
     ('md5', 'f8290f2d593a05ea811edbd3bff6eacc'),
     ('sha1', 'da892cf09cf37a5f3aebed596652d209193c47eb'))
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
    )['data']
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
