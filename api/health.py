from flask import Blueprint, current_app

from api.client import Client
from api.errors import AuthenticationRequiredError
from api.utils import get_key, jsonify_data

health_api = Blueprint('health', __name__)


@health_api.route('/health', methods=['POST'])
def health():
    key = get_key()

    if key is None:
        raise AuthenticationRequiredError

    url = current_app.config['AVOTX_URL']
    headers = {'User-Agent': current_app.config['CTR_USER_AGENT']}

    client = Client(key, url, headers=headers)
    _ = client.query('/api/v1/user/me')

    return jsonify_data({'status': 'ok'})
