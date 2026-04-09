"""Typeshed override for shutil — declares rmtree as plain def.

The real typeshed models rmtree as `_RmtreeType` Protocol, which Pysa
cannot resolve through module-level variable access. This override
declares it as a plain function so Pysa can match it to our sink model.
"""

from os import PathLike
from typing import Any, Callable

def rmtree(
    path: str | PathLike[str],
    ignore_errors: bool = ...,
    onerror: Callable[..., Any] | None = ...,
) -> None: ...

def copy(src: str | PathLike[str], dst: str | PathLike[str]) -> str: ...
def copy2(src: str | PathLike[str], dst: str | PathLike[str]) -> str: ...
def move(src: str | PathLike[str], dst: str | PathLike[str]) -> str: ...
