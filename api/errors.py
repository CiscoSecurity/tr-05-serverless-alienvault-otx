class RelayError(Exception):
    """Generic base class representing one particular type of Relay errors."""

    CODE = 'oops'
    MESSAGE = 'Something went wrong.'
    TYPE = 'fatal'

    def __init__(self, detail=''):
        message = self.MESSAGE
        if detail:
            message += f' {detail}.'

        super().__init__(message)

        self.message = message

    def json(self):
        return {
            'code': self.CODE,
            'message': self.message,
            'type': self.TYPE,
        }


class InvalidPayloadReceivedError(RelayError):
    CODE = 'invalid payload received'
    MESSAGE = 'Invalid JSON payload received.'


class AuthenticationRequiredError(RelayError):
    CODE = 'authentication required'
    MESSAGE = 'Authentication required.'
