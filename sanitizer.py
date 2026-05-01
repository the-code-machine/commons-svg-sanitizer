"""
Walks an SVG tree and strips anything outside the Commons allow-list.
Returns (cleaned_bytes, issues_list).
"""

from defusedxml.lxml import fromstring as safe_fromstring
from lxml import etree

from rules import (
    ALLOWED_ELEMENTS,
    DISALLOWED_ELEMENTS,
    EVENT_HANDLER_PREFIX,
    SAFE_URL_PREFIXES,
    DANGEROUS_STYLE_PATTERNS,
)


def _localname(tag: str) -> str:
    """Strip XML namespace from a tag name."""
    return tag.split("}", 1)[-1] if "}" in tag else tag


def sanitize_svg(svg_bytes: bytes):
    issues = []

    # 1. Safe parse (defusedxml blocks XXE/billion-laughs/external entities)
    try:
        root = safe_fromstring(svg_bytes)
    except Exception as e:
        return None, [{"severity": "blocker", "message": f"XML parse error: {e}"}]

    # 2. Confirm root is <svg>
    if _localname(root.tag) != "svg":
        return None, [{"severity": "blocker", "message": "Root element is not <svg>"}]

    # 3. Walk + strip
    for el in list(root.iter()):
        tag = _localname(el.tag)
        parent = el.getparent()

        # Block list
        if tag in DISALLOWED_ELEMENTS:
            issues.append({
                "severity": "blocker",
                "type": "element",
                "name": tag,
                "message": f"Removed <{tag}> — disallowed by Commons",
            })
            if parent is not None:
                parent.remove(el)
            continue

        # Allow list (anything not in either set is treated as warning + removed)
        if tag not in ALLOWED_ELEMENTS:
            issues.append({
                "severity": "warning",
                "type": "element",
                "name": tag,
                "message": f"Removed unknown element <{tag}>",
            })
            if parent is not None:
                parent.remove(el)
            continue

        # Attribute scrub
        for attr in list(el.attrib.keys()):
            attr_local = _localname(attr).lower()
            value = (el.attrib.get(attr) or "").strip()
            value_lower = value.lower()

            # 3a. Event handlers (onclick, onload, etc.)
            if attr_local.startswith(EVENT_HANDLER_PREFIX):
                issues.append({
                    "severity": "blocker",
                    "type": "attribute",
                    "name": attr_local,
                    "element": tag,
                    "message": f"Removed event handler {attr_local}= on <{tag}>",
                })
                del el.attrib[attr]
                continue

            # 3b. Hyperlinks
            if attr_local == "href":
                if not any(value_lower.startswith(p) for p in SAFE_URL_PREFIXES):
                    issues.append({
                        "severity": "blocker",
                        "type": "attribute",
                        "name": attr_local,
                        "element": tag,
                        "message": f"Removed unsafe URL in {attr_local}= on <{tag}>",
                    })
                    del el.attrib[attr]
                    continue

            # 3c. Inline style smuggling JS
            if attr_local == "style":
                if any(p in value_lower for p in DANGEROUS_STYLE_PATTERNS):
                    issues.append({
                        "severity": "blocker",
                        "type": "attribute",
                        "name": "style",
                        "element": tag,
                        "message": f"Removed dangerous style on <{tag}>",
                    })
                    del el.attrib[attr]
                    continue

    cleaned = etree.tostring(root, xml_declaration=True, encoding="utf-8", pretty_print=True)
    return cleaned, issues