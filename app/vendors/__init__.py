"""Vendor fakes, one module per vendor.

Each module exposes a FastAPI ``router`` (an ``APIRouter``) with its routes under
``/<vendor>/...``; ``app.main`` includes every router found here, so adding a vendor
never touches ``main.py``. Test data comes from Faker with the faker-cti providers
(``app.fake``).
"""

import importlib
import pkgutil

from fastapi import APIRouter


def routers() -> list[APIRouter]:
    found = []
    for module_info in sorted(pkgutil.iter_modules(__path__), key=lambda m: m.name):
        module = importlib.import_module(f"{__name__}.{module_info.name}")
        router = getattr(module, "router", None)
        if isinstance(router, APIRouter):
            found.append(router)
    return found
