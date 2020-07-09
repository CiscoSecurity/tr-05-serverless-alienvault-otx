from abc import ABC, abstractmethod
from inspect import isabstract
from typing import Optional, Dict, Union, List
from urllib.parse import quote

from api.bundle import Bundle
from api.client import Client
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
        """The AVOTX category for the class of observables."""

    def __init__(self, value: str) -> None:
        self.value = value

    def __str__(self) -> str:
        return self.value

    def __repr__(self) -> str:
        return f'{self.__class__.__name__}({self.value!r})'

    def json(self) -> Dict[str, str]:
        return {'type': self.type(), 'value': self.value}

    def observe(self, client: Client) -> Bundle:
        """Build a CTIM bundle for the current observable."""

        bundle = Bundle()

        params = {'sort': '-created', 'q': self.value}

        data = client.query('/api/v1/search/pulses', params=params)

        observable = self.json()

        for pulse in data['results']:
            # Enrich each AVOTX pulse with some additional context in order to
            # simplify further mapping of that pulse into CTIM entities.
            pulse['indicator'] = next(
                indicator
                for indicator in pulse['indicators']
                if indicator['indicator'] == self.value
            )
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

    def observe(self, client: Client) -> Bundle:
        # The AVOTX API does not support searching for email addresses.
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

    def observe(self, client: Client) -> Bundle:
        # The AVOTX API does not support searching for IPv6 addresses.
        return Bundle()


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

    def observe(self, client: Client) -> Bundle:
        # The AVOTX API does not support searching for URLs.
        return Bundle()
