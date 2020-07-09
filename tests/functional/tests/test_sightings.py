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
    (('ip', '54.38.157.11'),
     ('domain', 'jsebnawkndwandawd.sh'),
     ('sha256',
      'af689a29dab28eedb5b2ee5bf0b94be2112d0881fad815fa082dc3b9d224fce0'),
     ('md5', 'f8290f2d593a05ea811edbd3bff6eacc'),
     ('sha1', 'da892cf09cf37a5f3aebed596652d209193c47eb'))
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
    )['data']
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
