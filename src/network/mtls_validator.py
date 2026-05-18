import logging
from functools import wraps
from typing import Callable, TypeVar

T = TypeVar("T")
log = logging.getLogger(__name__)


def log_call(fn: Callable[..., T]) -> Callable[..., T]:
    @wraps(fn)
    def wrapper(*args, **kwargs):
        log.debug("Calling %s", fn.__qualname__)
        result = fn(*args, **kwargs)
        log.debug("%s returned", fn.__qualname__)
        return result
    return wrapper

# rev 20260518134405-87ba90d5
