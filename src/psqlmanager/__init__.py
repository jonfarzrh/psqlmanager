"""psqlmanager: encrypted credential store and psql wrapper."""

from importlib.metadata import PackageNotFoundError, version as _pkg_version

try:
    __version__ = _pkg_version("psqlmanager")
except PackageNotFoundError:  # not installed (e.g., running directly from source)
    __version__ = "0+unknown"
