from abc import ABC, abstractmethod
from inspect import isabstract
from urllib.parse import quote


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
    def instance_for(cls, type, value):
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
    def type():
        """The CTIM type for the class of observables."""

    @staticmethod
    @abstractmethod
    def name():
        """The human-readable name for the class of observables."""

    @staticmethod
    @abstractmethod
    def category():
        """The AVOTX category for the class of observables."""

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return self.value

    def __repr__(self):
        return f'{self.__class__.__name__}({self.value!r})'

    def observe(self):
        """Build a bundle with CTIM entities for the current observable."""
        raise NotImplementedError

    def refer(self, url):
        """Build a reference to the current observable."""
        return {
            'id': f'ref-avotx-search-{self.type()}-{self._quote(self.value)}',
            'title': f'Search for this {self.name()}',
            'description': f'Lookup this {self.name()} on AlienVault OTX',
            'url': f'{url}/indicator/{self.category()}/{self.value}',
            'categories': ['Search', 'AlienVault OTX'],
        }

    @staticmethod
    def _quote(value):
        return quote(value, safe='')


class Domain(Observable):

    @staticmethod
    def type():
        return 'domain'

    @staticmethod
    def name():
        return 'domain'

    @staticmethod
    def category():
        return 'domain'


class Email(Observable):

    @staticmethod
    def type():
        return 'email'

    @staticmethod
    def name():
        return 'email'

    @staticmethod
    def category():
        return 'email'


class FileHash(Observable):

    @staticmethod
    def category():
        return 'file'


class MD5(FileHash):

    @staticmethod
    def type():
        return 'md5'

    @staticmethod
    def name():
        return 'MD5'


class SHA1(FileHash):

    @staticmethod
    def type():
        return 'sha1'

    @staticmethod
    def name():
        return 'SHA1'


class SHA256(FileHash):

    @staticmethod
    def type():
        return 'sha256'

    @staticmethod
    def name():
        return 'SHA256'


class IP(Observable):

    @staticmethod
    def type():
        return 'ip'

    @staticmethod
    def name():
        return 'IP'

    @staticmethod
    def category():
        return 'ip'


class IPv6(IP):

    @staticmethod
    def type():
        return 'ipv6'

    @staticmethod
    def name():
        return 'IPv6'


class URL(Observable):

    @staticmethod
    def type():
        return 'url'

    @staticmethod
    def name():
        return 'URL'

    @staticmethod
    def category():
        return 'url'
