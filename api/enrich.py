from functools import partial

from flask import Blueprint, current_app

from api.observables import Observable
from api.schemas import ObservableSchema
from api.utils import get_json, get_jwt, jsonify_data

enrich_api = Blueprint('enrich', __name__)


get_observables = partial(get_json, schema=ObservableSchema(many=True))


@enrich_api.route('/deliberate/observables', methods=['POST'])
def deliberate_observables():
    # There are no verdicts to extract.
    return jsonify_data({})


@enrich_api.route('/observe/observables', methods=['POST'])
def observe_observables():
    _ = get_observables()
    _ = get_jwt()
    return jsonify_data({})


@enrich_api.route('/refer/observables', methods=['POST'])
def refer_observables():
    observables = get_observables()

    data = []

    for observable in observables:
        observable = Observable.instance_for(**observable)
        if observable is None:
            continue

        url = current_app.config['AVOTX_URL']
        reference = observable.refer(url)

        data.append(reference)

    return jsonify_data(data)
