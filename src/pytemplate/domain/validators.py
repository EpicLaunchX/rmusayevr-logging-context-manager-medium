from functools import wraps

from pytemplate.domain.models import LogLevel


def validate_level(level):
    try:
        return LogLevel[level].value
    except KeyError as exc:
        raise ValueError(f"Invalid log level: {level}") from exc


def validate_log_level(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if "level" in kwargs:
            kwargs["level"] = validate_level(kwargs["level"])
        return func(*args, **kwargs)

    return wrapper
