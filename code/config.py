import json


class Config:
    settings = json.load(open('container_settings.json', 'r'))
    VERSION = settings['VERSION']

    CTR_USER_AGENT = (
        'SecureX Threat Response Integrations '
        '<tr-integrations-support@cisco.com>'
    )

    CTR_ENTITIES_LIMIT_DEFAULT = 100

    CTR_ENTITIES_LIMIT_MAX = 1000

    AVOTX_URL = 'https://otx.alienvault.com'
