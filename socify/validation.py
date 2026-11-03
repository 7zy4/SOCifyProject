"""Messages deliberately authored for users, separated from internal exceptions."""


class ValidationError(ValueError):
    def __init__(self, message: str):
        super().__init__(message)
        self.public_message = message


def public_error_message(error: BaseException, fallback: str) -> str:
    """Never serialize database, parser, filesystem, or other library exceptions."""
    if isinstance(error, ValidationError):
        return error.public_message[:500]
    return fallback
