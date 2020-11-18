from concurrent.futures import ThreadPoolExecutor
from functools import partial
from os import cpu_count

from flask import Blueprint, current_app, g

from api.bundle import Bundle
from api.client import Client
from api.errors import AuthenticationRequiredError
from api.observables import Observable
from api.schemas import ObservableSchema
from api.utils import get_json, get_key, jsonify_data

enrich_api = Blueprint('enrich', __name__)


get_observables = partial(get_json, schema=ObservableSchema(many=True))


@enrich_api.route('/deliberate/observables', methods=['POST'])
def deliberate_observables():
    # There are no verdicts to extract.
    return jsonify_data({})


@enrich_api.route('/observe/observables', methods=['POST'])
def observe_observables():
    input_observables = get_observables()

    g.bundle = Bundle()

    key = get_key()

    if key is None:
        raise AuthenticationRequiredError

    url = current_app.config['AVOTX_URL']
    headers = {'User-Agent': current_app.config['CTR_USER_AGENT']}

    client = Client(key, url, headers=headers)
    limit = current_app.config['CTR_ENTITIES_LIMIT']

    prepared_observables = []
    for input_observable in input_observables:
        prepared_observable = Observable.instance_for(**input_observable)
        if prepared_observable is not None:
            prepared_observables.append(prepared_observable)

    def make_bundle(observable):
        return observable.observe(client, limit=limit)

    workers_number = min((cpu_count() or 1) * 5, len(prepared_observables))
    with ThreadPoolExecutor(max_workers=workers_number) as executor:
        bundles = executor.map(make_bundle, prepared_observables)

    for bundle in bundles:
        g.bundle |= bundle

    data = g.bundle.json()

    return jsonify_data(data)


@enrich_api.route('/refer/observables', methods=['POST'])
def refer_observables():
    observables = get_observables()

    data = []

    url = current_app.config['AVOTX_URL']

    for observable in observables:
        observable = Observable.instance_for(**observable)
        if observable is None:
            continue

        reference = observable.refer(url)
        data.append(reference)

    return jsonify_data(data)
