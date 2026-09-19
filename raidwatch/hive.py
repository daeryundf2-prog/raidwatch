"""Minimal Windows registry hive (regf) reader — stdlib only.

Parses the on-disk hive format used by SYSTEM, SOFTWARE, SAM,
NTUSER.DAT, and Amcache.hve so we can extract structured artifacts
(ShimCache, USBSTOR, UserAssist, Run keys) instead of grepping raw
strings out of the file. Read-only; never writes.

Format notes:
- File starts with "regf" header (4096 bytes); hbin blocks follow at
  0x1000-aligned offsets. Cell indexes are offsets from the start of
  the hbin area (file offset = 0x1000 + cell_index).
- Cells begin with an int32 size (negative = allocated). nk = key
  node, vk = value, lf/lh/li/ri = subkey lists, sk = security.
- nk subkey count at +0x14 (stable) + +0x18 (volatile); subkey list
  offsets at +0x1C/+0x20; value count +0x24; value list +0x28;
  name length +0x48, name at +0x4C (ASCII when flag 0x0020 set).
- vk: name len +0x02, data size +0x04 (top bit set = inline data in
  the +0x08 data-offset field), type +0x0C, flags +0x10 (0x01 = ASCII
  name), name at +0x14.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path

HBIN_BASE = 0x1000
_NK_SUBKEY_COUNT = (0x14, 0x18)   # stable, volatile
_NK_SUBKEY_LIST = (0x1C, 0x20)
_REG_TYPES = {
    1: "REG_SZ", 2: "REG_EXPAND_SZ", 3: "REG_BINARY",
    4: "REG_DWORD", 5: "REG_DWORD_BIG_ENDIAN", 6: "REG_LINK",
    7: "REG_MULTI_SZ", 11: "REG_QWORD",
}


class HiveError(Exception):
    pass


@dataclass
class VkValue:
    name: str
    type_id: int
    data: bytes

    @property
    def type_name(self) -> str:
        return _REG_TYPES.get(self.type_id, f"REG_{self.type_id}")

    def text(self) -> str | None:
        """Decoded string for REG_SZ/EXPAND/MULTI; None otherwise."""
        if self.type_id in (1, 2):
            return self.data.decode("utf-16-le", errors="replace").rstrip("\x00")
        if self.type_id == 7:
            return self.data.decode("utf-16-le", errors="replace").rstrip("\x00")
        if self.type_id == 4 and len(self.data) >= 4:
            return str(struct.unpack_from("<I", self.data)[0])
        if self.type_id == 11 and len(self.data) >= 8:
            return str(struct.unpack_from("<Q", self.data)[0])
        return None


@dataclass
class NkKey:
    name: str
    offset: int
    last_write_ns: int | None = None
    subkey_offsets: list[int] = field(default_factory=list)
    value_offsets: list[int] = field(default_factory=list)


class Hive:
    """Read-only regf hive. Index every cell once, then walk by offset."""

    def __init__(self, data: bytes):
        if len(data) < HBIN_BASE + 0x24 or data[:4] != b"regf":
            raise HiveError("not a regf hive")
        self._data = data
        self._cells: dict[int, tuple[int, int]] = {}  # index -> (file_off, size)
        pos = HBIN_BASE
        while pos + 0x20 <= len(data):
            if data[pos:pos + 4] != b"hbin":
                break
            hbin_size = struct.unpack_from("<I", data, pos + 0x08)[0]
            if hbin_size < 0x20 or pos + hbin_size > len(data):
                hbin_size = min(hbin_size, len(data) - pos)
                if hbin_size < 0x20:
                    break
            cell = pos + 0x20
            end = pos + hbin_size
            while cell + 4 <= end:
                size = struct.unpack_from("<i", data, cell)[0]
                if size == 0:
                    break
                n = abs(size)
                if n < 4 or cell + n > end:
                    break
                if size < 0:  # allocated only
                    self._cells[cell - HBIN_BASE] = (cell, n)
                cell += n
            pos += hbin_size
        if not self._cells:
            raise HiveError("no cells found")
        root_idx = struct.unpack_from("<I", data, 0x24)[0]
        self._root_off = root_idx
        if self._root_off not in self._cells:
            raise HiveError("root cell missing")

    @classmethod
    def from_path(cls, path: Path | str) -> "Hive":
        return cls(Path(path).read_bytes())

    # -- low-level ---------------------------------------------------

    def _cell(self, index: int) -> tuple[int, int]:
        try:
            return self._cells[index]
        except KeyError:
            raise HiveError(f"cell 0x{index:x} not found")

    def _sig(self, index: int) -> bytes:
        off, size = self._cell(index)
        if size < 6:
            return b""
        return self._data[off + 4:off + 6]

    # -- keys ---------------------------------------------------------

    def _nk(self, index: int) -> NkKey:
        if self._sig(index) != b"nk":
            raise HiveError(f"cell 0x{index:x} is not nk")
        off, size = self._cell(index)
        d = self._data
        key = NkKey(name="", offset=index)
        if size < 0x50:
            return key
        ft = struct.unpack_from("<Q", d, off + 4 + 0x04)[0]
        if ft:
            key.last_write_ns = (ft - 116444736000000000) * 100
        sub_count = (
            struct.unpack_from("<I", d, off + 4 + _NK_SUBKEY_COUNT[0])[0]
            + struct.unpack_from("<I", d, off + 4 + _NK_SUBKEY_COUNT[1])[0]
        )
        for list_idx_off in _NK_SUBKEY_LIST:
            idx = struct.unpack_from("<I", d, off + 4 + list_idx_off)[0]
            if idx != 0xFFFFFFFF and idx in self._cells:
                key.subkey_offsets.extend(self._subkey_list(idx))
        key.subkey_offsets = key.subkey_offsets[:sub_count] if sub_count else key.subkey_offsets
        val_count = struct.unpack_from("<I", d, off + 4 + 0x24)[0]
        val_list = struct.unpack_from("<I", d, off + 4 + 0x28)[0]
        if val_count and val_list != 0xFFFFFFFF and val_list in self._cells:
            voff, vsize = self._cell(val_list)
            for i in range(val_count):
                if 4 + i * 4 + 4 <= vsize:
                    vidx = struct.unpack_from("<I", d, voff + 4 + i * 4)[0]
                    if vidx in self._cells:
                        key.value_offsets.append(vidx)
        name_len = struct.unpack_from("<H", d, off + 4 + 0x48)[0]
        flags = struct.unpack_from("<H", d, off + 4 + 0x02)[0]
        raw = d[off + 4 + 0x4C: off + 4 + 0x4C + min(name_len, size - 0x50)]
        key.name = (
            raw.decode("latin-1", errors="replace")
            if flags & 0x0020
            else raw.decode("utf-16-le", errors="replace")
        )
        return key

    def _subkey_list(self, index: int) -> list[int]:
        sig = self._sig(index)
        off, size = self._cell(index)
        d = self._data
        out: list[int] = []
        if sig in (b"lf", b"lh"):
            count = struct.unpack_from("<H", d, off + 6)[0]
            for i in range(count):
                e = off + 8 + i * 8
                if e + 4 <= off + size:
                    out.append(struct.unpack_from("<I", d, e)[0])
        elif sig == b"li":
            count = struct.unpack_from("<H", d, off + 6)[0]
            for i in range(count):
                e = off + 8 + i * 4
                if e + 4 <= off + size:
                    out.append(struct.unpack_from("<I", d, e)[0])
        elif sig == b"ri":
            count = struct.unpack_from("<H", d, off + 6)[0]
            for i in range(count):
                e = off + 8 + i * 4
                if e + 4 <= off + size:
                    sub = struct.unpack_from("<I", d, e)[0]
                    if sub in self._cells:
                        out.extend(self._subkey_list(sub))
        return out

    # -- values --------------------------------------------------------

    def _vk(self, index: int) -> VkValue:
        if self._sig(index) != b"vk":
            raise HiveError(f"cell 0x{index:x} is not vk")
        off, size = self._cell(index)
        d = self._data
        name_len = struct.unpack_from("<H", d, off + 4 + 0x02)[0]
        data_size = struct.unpack_from("<I", d, off + 4 + 0x04)[0]
        data_off = struct.unpack_from("<I", d, off + 4 + 0x08)[0]
        type_id = struct.unpack_from("<I", d, off + 4 + 0x0C)[0] & 0x7FFFFFFF
        flags = struct.unpack_from("<H", d, off + 4 + 0x10)[0]
        if data_size & 0x80000000:  # inline data (<=4 bytes in offset field)
            n = data_size & 0x7FFFFFFF
            data = d[off + 4 + 0x08: off + 4 + 0x08 + min(n, 4)]
        elif data_size == 0 or data_off == 0xFFFFFFFF:
            data = b""
        elif data_off in self._cells:
            doff, dsize = self._cell(data_off)
            data = d[doff + 4: doff + 4 + min(data_size, dsize - 4)]
        else:
            data = b""
        raw = d[off + 4 + 0x14: off + 4 + 0x14 + min(name_len, size - 0x18)]
        name = (
            raw.decode("latin-1", errors="replace")
            if flags & 0x0001
            else raw.decode("utf-16-le", errors="replace")
        )
        return VkValue(name=name, type_id=type_id, data=data)

    # -- public -------------------------------------------------------

    def root(self) -> NkKey:
        return self._nk(self._root_off)

    def subkeys(self, key: NkKey) -> list[NkKey]:
        out = []
        for idx in key.subkey_offsets:
            try:
                out.append(self._nk(idx))
            except HiveError:
                continue
        return out

    def values(self, key: NkKey) -> list[VkValue]:
        out = []
        for idx in key.value_offsets:
            try:
                out.append(self._vk(idx))
            except HiveError:
                continue
        return out

    def find(self, *parts: str) -> NkKey | None:
        """Walk a path like find('ControlSet001','Control','Enum')."""
        key = self.root()
        for part in parts:
            match = next(
                (k for k in self.subkeys(key) if k.name.lower() == part.lower()),
                None,
            )
            if match is None:
                return None
            key = match
        return key

    def subkey_names(self, key: NkKey) -> list[str]:
        return [k.name for k in self.subkeys(key)]
