import pytest
from ctrlibrary.core.utils import get_observables
from ctrlibrary.threatresponse.enrich import enrich_observe_observables
from tests.functional.tests.constants import MODULE_NAME


@pytest.mark.parametrize(
    'observable_type, observable',
    (('ipv6', '2111:14aa:1f10:0:1117:e16e:843d:f803'),
     ('url', 'http://test.com'),
     ('domain', 'qwerty.sh'),
     ('sha256',
      'f1816fc4e601c59b67bcfe740037e95820fca0ff2420b211c64bd0ddfdf4f567'),
     ('md5', 'f1250e8348792ec2ab75250bc26b34b9'),
     ('sha1', 'be100a4e5f2f9b4fb02aacea95d4cb5ec6b2b0fd'))
)
def test_positive_smoke_observe_observables_empty_observables(
        module_headers, observable, observable_type):
    """Perform testing for enrich observe observables endpoint to check that
     observable, on which AlienVault OTX doesn't have information, will return
     empty data

    ID: CCTRI-1695-8f48503a-5277-4578-9f38-8d31b2aaa3cb

    Steps:
        1. Send request to enrich observe observable endpoint

    Expectedresults:
        1. Check that data in response body contains empty dict from AlienVault
        OTX module

    Importance: Critical
    """
    observables = [{'type': observable_type, 'value': observable}]
    response_from_all_modules = enrich_observe_observables(
        payload=observables,
        **{'headers': module_headers}
    )

    alien_vault_data = response_from_all_modules['data']

    response_from_alien_vault = get_observables(alien_vault_data, MODULE_NAME)

    assert response_from_alien_vault['module'] == MODULE_NAME
    assert response_from_alien_vault['module_instance_id']
    assert response_from_alien_vault['module_type_id']

    assert response_from_alien_vault['data'] == {}
