"""prod.keys / title.keys loading and keyset access.

Key files use the hactool convention: one `name = hexvalue` per line,
`#` comments. prod.keys auto-discovery prefers citron (newest on this
machine), then Ryujinx/yuzu/Suyu/strato, then ~/.switch.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Final

from .errors import UnpackError

_KEY_TYPES: Final = ("application", "ocean", "system")
_ENV_KEYS: Final = "NUP_KEYS"


def _parse_key_file(path: Path) -> dict[str, bytes]:
    keys: dict[str, bytes] = {}
    try:
        if path.stat().st_size > 16 * 1024 * 1024:
            raise UnpackError(f"key file suspiciously large: {path}")
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise UnpackError(f"cannot read key file {path}: {exc}") from exc
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, _, value = line.partition("=")
        value = value.strip().replace(" ", "")
        if not value or len(value) % 2:
            continue
        try:
            keys[name.strip().lower()] = bytes.fromhex(value)
        except ValueError:
            continue
    return keys


class Keyset:
    """prod.keys values plus a title.keys rights-id map."""

    __slots__ = ("_keys", "titlekeys", "prod_path")

    def __init__(self, keys: dict[str, bytes], titlekeys: dict[str, bytes],
                 prod_path: Path | None) -> None:
        self._keys = keys
        self.titlekeys = titlekeys
        self.prod_path = prod_path

    # -- construction ---------------------------------------------------
    @classmethod
    def load(cls, prod_keys: Path | None = None,
             title_keys: Path | None = None) -> Keyset:
        prod = prod_keys or cls.discover()
        if prod is None or not prod.is_file():
            raise UnpackError(
                "prod.keys not found; pass --keys or set NUP_KEYS")
        keys = _parse_key_file(prod)
        if "header_key" not in keys:
            raise UnpackError(f"{prod} has no header_key")
        title: dict[str, bytes] = {}
        tpath = title_keys or cls.discover_title_keys(prod)
        if tpath is not None and tpath.is_file():
            for name, value in _parse_key_file(tpath).items():
                if len(name) == 32 and len(value) == 0x10:
                    title[name] = value
        return cls(keys, title, prod)

    @staticmethod
    def discover() -> Path | None:
        env = os.environ.get(_ENV_KEYS)
        if env:
            p = Path(env)
            if p.is_file():
                return p
        appdata = os.environ.get("APPDATA")
        cands: list[Path] = []
        if appdata:
            base = Path(appdata)
            cands += [
                base / "citron" / "keys" / "prod.keys",
                base / "Ryujinx" / "system" / "prod.keys",
                base / "yuzu" / "keys" / "prod.keys",
                base / "Suyu" / "keys" / "prod.keys",
                base / "strato" / "keys" / "prod.keys",
                base / "nxdumptool" / "keys" / "prod.keys",
            ]
        cands.append(Path.home() / ".switch" / "prod.keys")
        for p in cands:
            if p.is_file():
                return p
        return None

    @staticmethod
    def discover_title_keys(prod: Path) -> Path | None:
        sibling = prod.with_name("title.keys")
        if sibling.is_file():
            return sibling
        appdata = os.environ.get("APPDATA")
        if appdata:
            for sub in (("Ryujinx", "system"), ("yuzu", "keys"),
                        ("Suyu", "keys"), ("strato", "keys")):
                p = Path(appdata).joinpath(*sub, "title.keys")
                if p.is_file():
                    return p
        home = Path.home() / ".switch" / "title.keys"
        return home if home.is_file() else None

    # -- lookups --------------------------------------------------------
    def get(self, name: str) -> bytes | None:
        return self._keys.get(name)

    def require(self, name: str) -> bytes:
        value = self._keys.get(name)
        if value is None:
            raise UnpackError(f"missing key {name!r} in "
                              f"{self.prod_path or 'key file'}")
        return value

    @property
    def header_key(self) -> bytes:
        key = self.require("header_key")
        if len(key) != 0x20:
            raise UnpackError("header_key must be 32 bytes")
        return key

    def key_area_key(self, keygen: int, kaek_ind: int) -> bytes:
        if kaek_ind >= len(_KEY_TYPES):
            raise UnpackError(f"bad key area key index {kaek_ind}")
        return self.require(f"key_area_key_{_KEY_TYPES[kaek_ind]}_{keygen:02x}")

    def titlekek(self, keygen: int) -> bytes:
        return self.require(f"titlekek_{keygen:02x}")
