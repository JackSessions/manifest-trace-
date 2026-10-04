"""Builds tiny, valid compiled AXML documents by hand (byte for byte) and proves the parser reads them back
correctly. This is the part of the test suite that needs no real APK: it proves the binary format reader itself
is correct against the documented chunk layout, independent of any one real manifest's content."""
import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from manifesttrace import axml  # noqa: E402


def utf8_string_pool(strings: list[str]) -> bytes:
    """A minimal UTF-8 string pool chunk containing exactly these strings, in order."""
    body = b""
    offsets = []
    for s in strings:
        offsets.append(len(body))
        raw = s.encode("utf-8")
        body += bytes([len(raw)]) + bytes([len(raw)]) + raw + b"\x00"
    header_size = 28
    strings_start = header_size + 4 * len(strings)
    size = strings_start + len(body)
    header = struct.pack("<HHIIIIII", 0x0001, header_size, size, len(strings), 0, 1 << 8, strings_start, 0)
    return header + struct.pack(f"<{len(strings)}I", *offsets) + body


def start_element(idx: dict, name: str, attrs: list[tuple[str, str | None, object]]) -> bytes:
    """attrs: (local_name, namespace_or_None, value) where value is a str (TYPE_STRING) or bool (TYPE_INT_BOOLEAN)."""
    attr_bytes = b""
    for local, ns, value in attrs:
        ns_idx = idx[ns] if ns else -1
        if isinstance(value, bool):
            attr_bytes += struct.pack("<iiiHBBI", ns_idx, idx[local], -1, 8, 0, axml.TYPE_INT_BOOLEAN, 0xFFFFFFFF if value else 0)
        else:
            attr_bytes += struct.pack("<iiiHBBI", ns_idx, idx[local], idx[value], 8, 0, axml.TYPE_STRING, idx[value])
    body = struct.pack("<Ii", 0, -1) + struct.pack("<iiHHHHHH", -1, idx[name], 20, 20, len(attrs), 0xFFFF, 0xFFFF, 0xFFFF) + attr_bytes
    size = 8 + len(body)
    return struct.pack("<HHI", axml.RES_XML_START_ELEMENT_TYPE, 16, size) + body


def end_element(idx: dict, name: str) -> bytes:
    body = struct.pack("<Ii", 0, -1) + struct.pack("<ii", -1, idx[name])
    return struct.pack("<HHI", axml.RES_XML_END_ELEMENT_TYPE, 16, 8 + len(body)) + body


def build_doc(strings: list[str], elements: list[bytes]) -> bytes:
    pool = utf8_string_pool(strings)
    body = pool + b"".join(elements)
    return struct.pack("<HHI", 0x0003, 8, 8 + len(body)) + body


class AxmlRoundTripTests(unittest.TestCase):
    def test_a_single_element_with_a_string_and_boolean_attribute(self):
        strings = ["manifest", "package", "com.example.app", "application", "debuggable"]
        idx = {s: i for i, s in enumerate(strings)}
        doc = build_doc(strings, [
            start_element(idx, "manifest", [("package", None, "com.example.app")]),
            start_element(idx, "application", [("debuggable", None, True)]),
            end_element(idx, "application"),
            end_element(idx, "manifest"),
        ])
        root = axml.parse(doc)
        self.assertEqual(root.name, "manifest")
        self.assertEqual(root.attr("package"), "com.example.app")
        app = root.findall("application")
        self.assertEqual(len(app), 1)
        self.assertIs(app[0].attr("debuggable"), True)

    def test_nesting_and_siblings(self):
        strings = ["manifest", "application", "activity", "name", "a", "b", "c"]
        idx = {s: i for i, s in enumerate(strings)}
        doc = build_doc(strings, [
            start_element(idx, "manifest", []),
            start_element(idx, "application", []),
            start_element(idx, "activity", [("name", None, "a")]),
            end_element(idx, "activity"),
            start_element(idx, "activity", [("name", None, "b")]),
            end_element(idx, "activity"),
            end_element(idx, "application"),
            end_element(idx, "manifest"),
        ])
        root = axml.parse(doc)
        acts = root.findall("application")[0].findall("activity")
        self.assertEqual([a.attr("name") for a in acts], ["a", "b"])

    def test_boolean_false_is_not_true(self):
        strings = ["manifest", "exported"]
        idx = {s: i for i, s in enumerate(strings)}
        doc = build_doc(strings, [start_element(idx, "manifest", [("exported", None, False)]), end_element(idx, "manifest")])
        root = axml.parse(doc)
        self.assertIs(root.attr("exported"), False)

    def test_too_short_input_raises_a_clean_error(self):
        with self.assertRaises(axml.AxmlError):
            axml.parse(b"\x00\x01")

    def test_namespaced_attribute_is_recognised_as_android_ns(self):
        strings = ["manifest", "exported", "http://schemas.android.com/apk/res/android"]
        idx = {s: i for i, s in enumerate(strings)}
        attr_bytes = struct.pack("<iiiHBBI", idx["http://schemas.android.com/apk/res/android"], idx["exported"], -1, 8, 0, axml.TYPE_INT_BOOLEAN, 0xFFFFFFFF)
        body = struct.pack("<Ii", 0, -1) + struct.pack("<iiHHHHHH", -1, idx["manifest"], 20, 20, 1, 0xFFFF, 0xFFFF, 0xFFFF) + attr_bytes
        el = struct.pack("<HHI", axml.RES_XML_START_ELEMENT_TYPE, 16, 8 + len(body)) + body
        doc = build_doc(strings, [el, end_element(idx, "manifest")])
        root = axml.parse(doc)
        self.assertTrue(root.attrs["exported"].is_android_ns)


if __name__ == "__main__":
    unittest.main()
