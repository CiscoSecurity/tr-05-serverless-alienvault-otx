from ctrlibrary.core.utils import get_observables
from ctrlibrary.threatresponse.enrich import enrich_post_health
from tests.functional.tests.constants import MODULE_NAME


def test_positive_smoke_enrich_health(module_headers):
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
    response_from_all_modules = enrich_post_health(
        **{'headers': module_headers}
    )['data']
    health_from_alien_vault = get_observables(response_from_all_modules,
                                              MODULE_NAME)
    assert health_from_alien_vault['module'] == MODULE_NAME
    assert health_from_alien_vault['module_instance_id']
    assert health_from_alien_vault['module_type_id']
    assert health_from_alien_vault['data']['status'] == 'ok'
