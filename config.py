import os

from uuid import NAMESPACE_X500

from version import VERSION


class Config:
    VERSION = VERSION

    SECRET_KEY = os.environ.get('SECRET_KEY', None)

    CTR_USER_AGENT = (
        'Cisco Threat Response Integrations '
        '<tr-integrations-support@cisco.com>'
    )

    CTR_ENTITIES_LIMIT_DEFAULT = 100

    try:
        CTR_ENTITIES_LIMIT = int(os.environ['CTR_ENTITIES_LIMIT'])
        assert CTR_ENTITIES_LIMIT > 0
    except (KeyError, ValueError, AssertionError):
        CTR_ENTITIES_LIMIT = CTR_ENTITIES_LIMIT_DEFAULT

    CTR_ENTITIES_LIMIT_MAX = 1000

    if CTR_ENTITIES_LIMIT > CTR_ENTITIES_LIMIT_MAX:
        CTR_ENTITIES_LIMIT = CTR_ENTITIES_LIMIT_MAX

    NAMESPACE_BASE = NAMESPACE_X500

    AVOTX_URL = 'https://otx.alienvault.com'
