"""Turns a parsed AXML tree into the plain structures the checks work on.

This is the "what does the app declare" layer: component exposure, backup policy, debug flags, network policy.
Nothing here decides whether something is a problem, that is checks.py's job; this module just reads what the
manifest actually says, the same separation PhantomTrace and RuntimeTrace use between reading data and judging it.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import axml

EXPORT_DEFAULT_KINDS = ("activity", "activity-alias", "service", "receiver")   # default: true iff it has an intent-filter
PROVIDER_KIND = "provider"                                                     # default depends on targetSdkVersion


@dataclass
class IntentFilter:
    actions: list[str] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)

    @property
    def is_launcher(self) -> bool:
        return "android.intent.action.MAIN" in self.actions and "android.intent.category.LAUNCHER" in self.categories


@dataclass
class Component:
    kind: str                       # activity, activity-alias, service, receiver, provider
    name: str
    exported_attr: bool | None      # None if not explicitly set in the manifest
    permission: str | None
    read_permission: str | None = None      # provider only
    write_permission: str | None = None     # provider only
    grant_uri_permissions: bool = False     # provider only
    authorities: str = ""                   # provider only
    intent_filters: list[IntentFilter] = field(default_factory=list)
    has_path_permissions: bool = False      # provider only: narrower per-path grants exist

    def effective_exported(self, target_sdk: int) -> bool:
        """What the OS actually does at install/runtime when `exported` is not explicit."""
        if self.exported_attr is not None:
            return self.exported_attr
        if self.kind == PROVIDER_KIND:
            return target_sdk < 17
        return any(self.intent_filters)

    def is_protected(self) -> bool:
        if self.kind == PROVIDER_KIND:
            return bool(self.permission) or bool(self.read_permission and self.write_permission)
        return bool(self.permission)


@dataclass
class Manifest:
    path: str
    package: str
    min_sdk: int
    target_sdk: int
    debuggable: bool
    allow_backup: bool | None               # None: not set, defaults to true
    uses_cleartext_traffic: bool | None     # None: not set, default depends on target_sdk (true if < 28)
    has_network_security_config: bool
    components: list[Component] = field(default_factory=list)

    def effective_cleartext(self) -> bool:
        if self.uses_cleartext_traffic is not None:
            return self.uses_cleartext_traffic
        if self.has_network_security_config:
            return False                    # a config is assumed to set its own policy; not this tool's business
        return self.target_sdk < 28


def _int_attr(el: axml.Element, name: str, default: int = 0) -> int:
    v = el.attr(name)
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def _intent_filters(el: axml.Element) -> list[IntentFilter]:
    out = []
    for f in el.findall("intent-filter"):
        out.append(IntentFilter(actions=[a.attr("name") for a in f.findall("action") if a.attr("name")],
                                categories=[c.attr("name") for c in f.findall("category") if c.attr("name")]))
    return out


def _component(kind: str, el: axml.Element) -> Component:
    c = Component(kind=kind, name=el.attr("name") or "?", exported_attr=el.attr("exported"),
                  permission=el.attr("permission"), intent_filters=_intent_filters(el))
    if kind == PROVIDER_KIND:
        c.read_permission = el.attr("readPermission")
        c.write_permission = el.attr("writePermission")
        c.grant_uri_permissions = bool(el.attr("grantUriPermissions", False))
        c.authorities = el.attr("authorities") or ""
        c.has_path_permissions = bool(el.findall("path-permission") or el.findall("grant-uri-permission"))
    return c


def from_axml(root: axml.Element, path: str = "") -> Manifest:
    if root.name != "manifest":
        raise ValueError(f"expected a <manifest> root element, got <{root.name}>")
    sdk_el = (root.findall("uses-sdk") or [None])[0]
    min_sdk = _int_attr(sdk_el, "minSdkVersion", 1) if sdk_el else 1
    target_sdk = _int_attr(sdk_el, "targetSdkVersion", min_sdk) if sdk_el else min_sdk
    app = (root.findall("application") or [None])[0]
    components: list[Component] = []
    debuggable = allow_backup = cleartext = None
    has_nsc = False
    if app is not None:
        debuggable = bool(app.attr("debuggable", False))
        allow_backup = app.attr("allowBackup")
        cleartext = app.attr("usesCleartextTraffic")
        has_nsc = bool(app.attr("networkSecurityConfig"))
        for kind in ("activity", "activity-alias", "service", "receiver", "provider"):
            for el in app.findall(kind):
                components.append(_component(kind, el))
    return Manifest(path=path, package=root.attr("package") or "", min_sdk=min_sdk, target_sdk=target_sdk,
                    debuggable=bool(debuggable), allow_backup=allow_backup, uses_cleartext_traffic=cleartext,
                    has_network_security_config=has_nsc, components=components)


def load(apk_path: str) -> Manifest:
    import zipfile
    try:
        with zipfile.ZipFile(apk_path) as z:
            try:
                data = z.read("AndroidManifest.xml")
            except KeyError:
                raise axml.AxmlError(f"{apk_path} has no AndroidManifest.xml: is it really an APK?") from None
    except zipfile.BadZipFile:
        raise axml.AxmlError(f"{apk_path} is not a valid .apk (not a zip file)") from None
    return from_axml(axml.parse(data), path=apk_path)
