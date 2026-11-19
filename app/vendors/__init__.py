"""Vendor fakes, one module per vendor.

Each module exposes a FastAPI ``router`` (an ``APIRouter``) with its routes under
``/<vendor>/...``; ``app.main`` includes every router found here, so adding a vendor
never touches ``main.py``. Test data comes from Faker with the faker-cti providers
(``app.fake``).

A module may also list the real hosts of its vendor in ``HOSTS`` (fnmatch patterns
such as ``*.vendor.com``): a proxy in front of ofapi then sends the requests made to
those hosts to the module's routes, so code with a hardcoded vendor URL reaches the
fake too.

``reload_into`` (``POST /_control/reload``) picks up new and changed modules while
ofapi runs, keeping the scripted rules and the journal.
"""

import importlib
import pkgutil
import sys
from pathlib import Path

from fastapi import APIRouter, FastAPI

# module name -> (file mtime, routes it added to the app)
_loaded: dict[str, tuple[float, list]] = {}


def _modules() -> list[str]:
    found = pkgutil.iter_modules(__path__)
    return sorted(m.name for m in found if not m.name.startswith("_"))


def _mtime(name: str) -> float:
    return (Path(__path__[0]) / f"{name}.py").stat().st_mtime


def routers() -> list[APIRouter]:
    found = []
    for name in _modules():
        module = importlib.import_module(f"{__name__}.{name}")
        router = getattr(module, "router", None)
        if isinstance(router, APIRouter):
            found.append(router)
    return found


# module name -> why it could not be loaded (it is skipped, the others keep working)
broken: dict[str, str] = {}


def include_all(app: FastAPI) -> None:
    for name in _modules():
        _try_include(app, name)


def _try_include(app: FastAPI, name: str) -> bool:
    try:
        _include(app, name)
    except Exception as err:  # one broken fake must not take the others down
        broken[name] = f"{type(err).__name__}: {err}"
        _loaded[name] = (_mtime(name), [])
        return False
    broken.pop(name, None)
    return True


def _include(app: FastAPI, name: str) -> None:
    qualified = f"{__name__}.{name}"
    module = (
        importlib.reload(sys.modules[qualified])
        if qualified in sys.modules
        else importlib.import_module(qualified)
    )
    router = getattr(module, "router", None)
    before = list(app.router.routes)
    if isinstance(router, APIRouter):
        app.include_router(router)
    added = [route for route in app.router.routes if route not in before]
    _loaded[name] = (_mtime(name), added)


def reload_into(app: FastAPI) -> list[str]:
    """(Re)load the modules new or changed since they were loaded; their names."""
    changed = []
    for name in _modules():
        if name in _loaded and _loaded[name][0] == _mtime(name):
            continue
        for route in _loaded.get(name, (0, []))[1]:
            app.router.routes.remove(route)
        if _try_include(app, name):
            changed.append(name)
    app.openapi_schema = None
    return changed


def hosts() -> dict[str, str]:
    """Real vendor host pattern -> path prefix of its fake."""
    mapping = {}
    for name in _modules():
        module = sys.modules.get(f"{__name__}.{name}")
        router = getattr(module, "router", None)
        for pattern in getattr(module, "HOSTS", []):
            prefix = router.prefix if isinstance(router, APIRouter) else f"/{name}"
            mapping[pattern] = prefix
    return mapping
