from abc import ABC, abstractmethod
from inspect import isabstract
from typing import Optional, Dict, Any
from urllib.parse import quote

from api.bundle import Bundle
from api.client import Client


def _concrete_subclasses_of(cls):
    subclasses = set()

    for subcls in cls.__subclasses__():
        if not isabstract(subcls):
            subclasses.add(subcls)

        subclasses.update(_concrete_subclasses_of(subcls))

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

    def observe(self, client: Client) -> Bundle:
        """Build a CTIM bundle for the current observable."""
        bundle = Bundle()

        # TODO: implement

        return bundle

    @staticmethod
    def _quote(value):
        return quote(value, safe='')

    def refer(self, url: str) -> Dict[str, Any]:
        """Build an AVOTX reference for the current observable."""
        return {
            'id': f'ref-avotx-search-{self.type()}-{self._quote(self.value)}',
            'title': f'Search for this {self.name()}',
            'description': f'Lookup this {self.name()} on AlienVault OTX',
            'url': f'{url}/indicator/{self.category()}/{self.value}',
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
