"""Lazy-loading helper: legitimate pattern, not malicious."""
import importlib


def get_backend(name):
    """Return the backend module by name. Imported on first use."""
    return importlib.import_module(f"my_package.backends.{name}")


__all__ = ["get_backend"]
