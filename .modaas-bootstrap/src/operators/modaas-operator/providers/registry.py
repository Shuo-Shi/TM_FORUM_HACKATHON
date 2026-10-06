"""Plugin registry for MoDaaS v2 asset providers.

Plugins register themselves at operator startup (via explicit imports). Runtime
dispatch is a dict lookup on (kind, provider) tuple."""

from typing import Type

from base.provider import AssetProvider


_REGISTRY: dict[tuple[str, str], Type[AssetProvider]] = {}


def register(cls: Type[AssetProvider]) -> Type[AssetProvider]:
    """Register a provider class. Can be used as a decorator."""
    if not cls.kind or not cls.provider:
        raise ValueError(f"{cls.__name__} must set class attrs `kind` and `provider`")
    key = (cls.kind, cls.provider)
    if key in _REGISTRY and _REGISTRY[key] is not cls:
        raise ValueError(
            f"plugin collision: {key} already registered to {_REGISTRY[key].__name__}, "
            f"cannot register {cls.__name__}"
        )
    _REGISTRY[key] = cls
    return cls


def get(kind: str, provider: str) -> AssetProvider:
    """Return a fresh instance of the plugin registered for (kind, provider)."""
    try:
        cls = _REGISTRY[(kind, provider)]
    except KeyError:
        raise LookupError(f"no plugin registered for kind={kind} provider={provider}")
    return cls()


def list_plugins() -> list[tuple[str, str]]:
    """All registered (kind, provider) pairs."""
    return sorted(_REGISTRY.keys())


def is_supported(kind: str, provider: str) -> bool:
    return (kind, provider) in _REGISTRY
