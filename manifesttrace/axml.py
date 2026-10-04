"""A from-scratch reader for Android's compiled binary XML format (AXML).

AndroidManifest.xml inside an .apk is not text: the Android build tools compile it into a binary chunk format
(string pool, then a stream of start/end element and namespace nodes, each referencing strings by index) so the
OS can parse it fast on-device. This reads that format directly with the standard library only. No androguard,
no Android SDK, no aapt: the same "read the real bytes yourself" approach as this author's NTFS and eBPF work.

Format reference: AOSP frameworks/base/include/androidfw/ResourceTypes.h (the public chunk layout), cross-checked
against real compiled manifests. Read-only: this only parses what it finds; it never writes to the APK.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field

# Chunk type codes (ResourceTypes.h)
RES_STRING_POOL_TYPE = 0x0001
RES_XML_START_NAMESPACE_TYPE = 0x0100
RES_XML_END_NAMESPACE_TYPE = 0x0101
RES_XML_START_ELEMENT_TYPE = 0x0102
RES_XML_END_ELEMENT_TYPE = 0x0103
RES_XML_RESOURCE_MAP_TYPE = 0x0180

TYPE_STRING = 0x03
TYPE_INT_DEC = 0x10
TYPE_INT_HEX = 0x11
TYPE_INT_BOOLEAN = 0x12

SORTED_FLAG = 1 << 0
UTF8_FLAG = 1 << 8


class AxmlError(Exception):
    pass


@dataclass
class Attr:
    namespace: str | None       # e.g. "http://schemas.android.com/apk/res/android", or None
    name: str
    value: object                # str, int, or bool, decoded per its Android typed-value tag

    @property
    def is_android_ns(self) -> bool:
        return bool(self.namespace) and self.namespace.endswith("apk/res/android")


@dataclass
class Element:
    name: str
    attrs: dict[str, Attr] = field(default_factory=dict)   # keyed by local attribute name
    children: list["Element"] = field(default_factory=list)
    line: int = 0

    def attr(self, local_name: str, default=None):
        a = self.attrs.get(local_name)
        return a.value if a is not None else default

    def findall(self, tag: str) -> list["Element"]:
        return [c for c in self.children if c.name == tag]


class _StringPool:
    def __init__(self, strings: list[str]) -> None:
        self.strings = strings

    def get(self, idx: int) -> str | None:
        if idx is None or idx < 0 or idx >= len(self.strings):
            return None
        return self.strings[idx]


def _read_string_pool(data: bytes, off: int, chunk_size: int) -> _StringPool:
    (string_count, style_count, flags, strings_start, styles_start) = struct.unpack_from("<IIIII", data, off + 8)
    offsets = struct.unpack_from(f"<{string_count}I", data, off + 28) if string_count else ()
    base = off + strings_start
    utf8 = bool(flags & UTF8_FLAG)
    out = []
    for o in offsets:
        p = base + o
        if utf8:
            # one or two bytes for the UTF-16 length (ignored, redundant with the UTF-8 one below), then the
            # UTF-8 length in the same 1-or-2-byte encoding, then that many UTF-8 bytes, then a NUL.
            _u16len, p = _read_len8(data, p)
            u8len, p = _read_len8(data, p)
            out.append(data[p:p + u8len].decode("utf-8", "replace"))
        else:
            u16len, p = _read_len16(data, p)
            raw = data[p:p + u16len * 2]
            out.append(raw.decode("utf-16-le", "replace"))
    return _StringPool(out)


def _read_len8(data: bytes, p: int) -> tuple[int, int]:
    first = data[p]
    if first & 0x80:
        length = ((first & 0x7F) << 8) | data[p + 1]
        return length, p + 2
    return first, p + 1


def _read_len16(data: bytes, p: int) -> tuple[int, int]:
    first = struct.unpack_from("<H", data, p)[0]
    if first & 0x8000:
        second = struct.unpack_from("<H", data, p + 2)[0]
        length = ((first & 0x7FFF) << 16) | second
        return length, p + 4
    return first, p + 2


def _decode_value(sp: _StringPool, raw_value_idx: int, data_type: int, value: int) -> object:
    if data_type == TYPE_STRING:
        return sp.get(raw_value_idx) if raw_value_idx >= 0 else sp.get(value)
    if data_type == TYPE_INT_BOOLEAN:
        return bool(value)
    if data_type in (TYPE_INT_DEC, TYPE_INT_HEX):
        return value
    # References, dimensions, colours etc: keep the raw string form if there was one, else the raw int.
    return sp.get(raw_value_idx) if raw_value_idx >= 0 else value


def parse(data: bytes) -> Element:
    """Parses a compiled AndroidManifest.xml (as raw bytes) into a tree rooted at the <manifest> element."""
    if len(data) < 8:
        raise AxmlError("too short to be a compiled binary XML file")
    doc_type, _hdr, _doc_size = struct.unpack_from("<HHI", data, 0)
    pos = 8
    sp: _StringPool | None = None
    stack: list[Element] = []
    root: Element | None = None
    n = len(data)
    while pos + 8 <= n:
        ctype, chdr, csize = struct.unpack_from("<HHI", data, pos)
        if csize <= 0 or pos + csize > n:
            break
        if ctype == RES_STRING_POOL_TYPE:
            sp = _read_string_pool(data, pos, csize)
        elif ctype == RES_XML_RESOURCE_MAP_TYPE:
            pass                                             # not needed: elements are matched by string name
        elif ctype == RES_XML_START_ELEMENT_TYPE:
            if sp is None:
                raise AxmlError("start-element chunk appeared before any string pool")
            # `chdr` already covers the full common node header (chunk header + lineNumber + comment, 16
            # bytes total): the attrExt struct (ns, name, attribute*) starts right at pos + chdr, not 8 past it.
            _line = struct.unpack_from("<I", data, pos + 8)[0]
            p = pos + chdr
            ns_idx, name_idx, attr_start, attr_size, attr_count, _id_idx, _cls_idx, _style_idx = \
                struct.unpack_from("<iiHHHHHH", data, p)
            name = sp.get(name_idx) or "?"
            el = Element(name=name, line=_line)
            ap = pos + chdr + attr_start
            for _ in range(attr_count):
                a_ns, a_name, a_raw, a_size, a_res0, a_type, a_data = struct.unpack_from("<iiiHBBI", data, ap)
                local = sp.get(a_name) or "?"
                el.attrs[local] = Attr(namespace=sp.get(a_ns) if a_ns >= 0 else None, name=local,
                                       value=_decode_value(sp, a_raw, a_type, a_data))
                ap += attr_size
            if stack:
                stack[-1].children.append(el)
            else:
                root = el
            stack.append(el)
        elif ctype == RES_XML_END_ELEMENT_TYPE:
            if stack:
                stack.pop()
        # START_NAMESPACE / END_NAMESPACE / CDATA chunks carry nothing this reader needs.
        pos += csize
    if root is None:
        raise AxmlError("no root <manifest> element found (not a valid compiled AndroidManifest.xml)")
    return root
