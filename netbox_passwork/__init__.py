from importlib.metadata import PackageNotFoundError, version

from .config import config

try:
    __version__ = version("netbox-passwork")
except PackageNotFoundError:
    __version__ = "dev"


__all__ = [
    "config",
]
