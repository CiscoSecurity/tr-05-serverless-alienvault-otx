from flask import Blueprint

from api.utils import query_api, jsonify_data

health_api = Blueprint('health', __name__)


@health_api.route('/health', methods=['POST'])
def health():
    _ = query_api('user/me')
    return jsonify_data({'status': 'ok'})
