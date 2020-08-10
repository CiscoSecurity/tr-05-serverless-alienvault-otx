from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor
from inspect import isabstract
from operator import itemgetter
from os import cpu_count
from typing import Optional, Dict, Union, List
from urllib.parse import quote

from api.bundle import Bundle
from api.client import Client
from api.errors import RelayError
from api.mappings import Sighting, Indicator, Relationship


def _concrete_subclasses_of(cls):
    attr = '_concrete_subclasses'

    if hasattr(cls, attr):
        return getattr(cls, attr)

    subclasses = set()

    for subcls in cls.__subclasses__():
        if not isabstract(subcls):
            subclasses.add(subcls)

        subclasses.update(_concrete_subclasses_of(subcls))

    setattr(cls, attr, subclasses)

    return subclasses


class Observable(ABC):
    """Abstract base class representing one particular type of observables."""

    @classmethod
    def instance_for(cls, type: str, value: str) -> Optional['Observable']:
        """
        Create an observable instance of the given type with the given value.

        If the current class does not have any concrete subclasses that
        correspond to the given observable type, then `None` is returned.
        """

        for subcls in _concrete_subclasses_of(cls):
            if subcls.type() == type:
                return subcls(value)

    @staticmethod
    @abstractmethod
    def type() -> str:
        """The CTIM type for the class of observables."""

    @staticmethod
    @abstractmethod
    def name() -> str:
        """The human-readable name for the class of observables."""

    @staticmethod
    @abstractmethod
    def category() -> str:
        """The AVOTX indicator category for the class of observables."""

    def __init__(self, value: str) -> None:
        self.value = value

    def __str__(self) -> str:
        return self.value

    def __repr__(self) -> str:
        return f'{self.__class__.__name__}({self.value!r})'

    def json(self) -> Dict[str, str]:
        return {'type': self.type(), 'value': self.value}

    def observe(self, client: Client, limit: Optional[int] = None) -> Bundle:
        """Build a CTIM bundle for the current observable."""

        bundle = Bundle()

        # Implement a workaround instead of using the "/api/v1/search/pulses"
        # endpoint as it works too slow and is not really optimizable...

        category = {
            'ip': 'IPv4',
            'ipv6': 'IPv6',
        }.get(
            self.type(),
            self.category(),
        )

        endpoint = (
            f'/api/v1/indicators/{category}/'
            f"{quote(self.value, safe='@:')}/general"
        )

        data = client.query(endpoint)
        if data is None:
            return bundle

        # Make sure to filter out redundant pulses that do not match anyway.
        pulses = [
            pulse
            for pulse in data['pulse_info']['pulses']
            if data['base_indicator']['type'] in pulse['indicator_type_counts']
        ]
        if not pulses:
            return bundle

        def indicator_for(pulse, page=1):
            # This limit provides a decent tradeoff between the number of
            # requests to be made and the size of each response coming back.
            limit = 10000

            endpoint = f"/api/v1/pulses/{pulse['id']}/indicators"
            params = {'sort': '-created', 'limit': limit, 'page': page}

            data = client.query(endpoint, params=params)

            for indicator in data['results']:
                if indicator['indicator'] == self.value:
                    return indicator

            if data['next'] is None:
                return None

            return indicator_for(pulse, page=(page + 1))

        with ThreadPoolExecutor(
            max_workers=min(len(pulses), (cpu_count() or 1) * 5)
        ) as executor:
            iterator = executor.map(indicator_for, pulses)

        indicators = []

        while True:
            try:
                indicator = next(iterator)
            except RelayError:
                continue
            except StopIteration:
                break
            else:
                if indicator is None:
                    continue
                indicators.append(indicator)

        indicators.sort(key=itemgetter('created'), reverse=True)

        if limit is None:
            limit = len(indicators)

        indicators = indicators[:limit]

        observable = self.json()

        for indicator in indicators:
            pulse = next(
                pulse
                for pulse in pulses
                if pulse['id'] == indicator['pulse_key']
            )

            # Enrich each AVOTX pulse with some additional context in order to
            # simplify further mapping of that pulse into CTIM entities.
            pulse['indicator'] = indicator
            pulse['observable'] = observable
            pulse['url'] = client.url

            sighting = Sighting.map(pulse)
            indicator = Indicator.map(pulse)
            relationship = Relationship.map(sighting, indicator)

            bundle.add(sighting)
            bundle.add(indicator)
            bundle.add(relationship)

        return bundle

    def refer(self, url: str) -> Dict[str, Union[str, List[str]]]:
        """Build an AVOTX reference for the current observable."""
        return {
            'id': (
                f"ref-avotx-search-{self.type()}-{quote(self.value, safe='')}"
            ),
            'title': f'Search for this {self.name()}',
            'description': f'Lookup this {self.name()} on AlienVault OTX',
            'url': (
                f"{url.rstrip('/')}/indicator/{self.category()}/"
                f"{quote(self.value, safe='@:')}"
            ),
            'categories': ['Search', 'AlienVault OTX'],
        }


class Domain(Observable):

    @staticmethod
    def type() -> str:
        return 'domain'

    @staticmethod
    def name() -> str:
        return 'domain'

    @staticmethod
    def category() -> str:
        return 'domain'


class Email(Observable):

    @staticmethod
    def type() -> str:
        return 'email'

    @staticmethod
    def name() -> str:
        return 'email'

    @staticmethod
    def category() -> str:
        return 'email'

    def observe(self, client: Client, limit: Optional[int] = None) -> Bundle:
        # The AVOTX API does not support searching for email addresses as the
        # "/api/v1/indicators/email/{email}/general" endpoint does not exist.
        return Bundle()


class FileHash(Observable):

    @staticmethod
    def category() -> str:
        return 'file'


class MD5(FileHash):

    @staticmethod
    def type() -> str:
        return 'md5'

    @staticmethod
    def name() -> str:
        return 'MD5'


class SHA1(FileHash):

    @staticmethod
    def type() -> str:
        return 'sha1'

    @staticmethod
    def name() -> str:
        return 'SHA1'


class SHA256(FileHash):

    @staticmethod
    def type() -> str:
        return 'sha256'

    @staticmethod
    def name() -> str:
        return 'SHA256'


class IP(Observable):

    @staticmethod
    def type() -> str:
        return 'ip'

    @staticmethod
    def name() -> str:
        return 'IP'

    @staticmethod
    def category() -> str:
        return 'ip'


class IPv6(IP):

    @staticmethod
    def type() -> str:
        return 'ipv6'

    @staticmethod
    def name() -> str:
        return 'IPv6'


class URL(Observable):

    @staticmethod
    def type() -> str:
        return 'url'

    @staticmethod
    def name() -> str:
        return 'URL'

    @staticmethod
    def category() -> str:
        return 'url'
