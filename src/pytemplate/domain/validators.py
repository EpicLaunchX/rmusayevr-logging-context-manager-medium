from functools import wraps

from pytemplate.domain.models import LogLevel


def validate_log_level(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if "level" in kwargs:
            kwargs["level"] = LogLevel[kwargs["level"]].value
        return func(*args, **kwargs)

    return wrapper
