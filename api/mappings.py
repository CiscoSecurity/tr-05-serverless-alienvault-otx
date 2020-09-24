from abc import ABC, abstractmethod
from uuid import uuid4, uuid5
from typing import Dict, Any
from flask import current_app

JSON = Dict[str, Any]


class Mapping(ABC):

    @classmethod
    @abstractmethod
    def map(cls, *args, **kwargs) -> JSON:
        pass


CTIM_DEFAULTS = {
    'schema_version': '1.0.17',
}


def transient_id(entity, base_value=None):
    uuid = (uuid5(current_app.config['NAMESPACE_BASE'], base_value)
            if base_value else uuid4())
    return f'transient:{entity["type"]}-{uuid}'


class Sighting(Mapping):
    DEFAULTS = {
        'type': 'sighting',
        'confidence': 'High',
        'count': 1,
        'internal': False,
        'source': 'AlienVault OTX',
        **CTIM_DEFAULTS
    }

    @classmethod
    def map(cls, pulse: JSON) -> JSON:
        sighting: JSON = cls.DEFAULTS.copy()

        sighting['id'] = transient_id(sighting)

        sighting['observed_time'] = {
            'start_time': pulse['indicator']['created'] + 'Z'
        }
        sighting['observed_time']['end_time'] = (
            sighting['observed_time']['start_time']
        )

        sighting['description'] = pulse['description'] or ''

        sighting['external_ids'] = [pulse['id']]

        sighting['observables'] = [pulse['observable']]

        sighting['source_uri'] = (
            f"{pulse['url'].rstrip('/')}/pulse/{pulse['id']}"
        )

        sighting['title'] = pulse['name']

        sighting['tlp'] = pulse['TLP']

        return sighting


class Indicator(Mapping):
    DEFAULTS = {
        'type': 'indicator',
        'confidence': 'High',
        'source': 'AlienVault OTX',
        **CTIM_DEFAULTS
    }

    @classmethod
    def map(cls, pulse: JSON) -> JSON:
        indicator: JSON = cls.DEFAULTS.copy()

        indicator['id'] = transient_id(indicator, pulse['id'])

        indicator['producer'] = pulse['author']['username']

        indicator['valid_time'] = {
            'start_time': pulse['indicator']['created'] + 'Z'
        }
        if pulse['indicator']['expiration']:
            indicator['valid_time']['end_time'] = (
                pulse['indicator']['expiration'] + 'Z'
            )

        indicator['external_ids'] = [pulse['id']]

        indicator['short_description'] = pulse['description'] or ''

        indicator['source_uri'] = (
            f"{pulse['url'].rstrip('/')}/pulse/{pulse['id']}"
        )

        indicator['tags'] = pulse['tags']

        indicator['title'] = pulse['name']

        indicator['tlp'] = pulse['TLP']

        return indicator


class Relationship(Mapping):
    DEFAULTS = {
        'type': 'relationship',
        'relationship_type': 'member-of',
        **CTIM_DEFAULTS
    }

    @classmethod
    def map(cls, sighting: JSON, indicator: JSON) -> JSON:
        relationship: JSON = cls.DEFAULTS.copy()

        relationship['id'] = transient_id(relationship)

        relationship['source_ref'] = sighting['id']

        relationship['target_ref'] = indicator['id']

        return relationship
