from abc import ABC, abstractmethod
from inspect import isabstract
from urllib.parse import quote


class Observable(ABC):

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

    def refer(self):
        return {
            'id': (
                'ref-avotx-search-'
                f'{self.type()}-{quote(self.value, safe="")}'
            ),
            'title': f'Search for this {self.name()}',
            'description': f'Lookup this {self.name()} on AlienVault OTX',
            'url': (
                'https://otx.alienvault.com/indicator/'
                f'{self.category()}/{self.value}'
            ),
            'categories': ['Search', 'AlienVault OTX'],
        }


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


def _concrete_subclasses_of(cls):
    subclasses = set()

    for subcls in cls.__subclasses__():
        if not isabstract(subcls):
            subclasses.add(subcls)

        subclasses.update(_concrete_subclasses_of(subcls))

    return subclasses


def observable_instance_for(type, value):
    for cls in _concrete_subclasses_of(Observable):
        if cls.type() == type:
            return cls(value)
