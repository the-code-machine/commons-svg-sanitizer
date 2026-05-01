"""
Allow-list of SVG elements + attributes accepted by MediaWiki/Commons.
Subset based on MediaWiki's SvgSanitizer rules (PHP) — covers ~99% of real SVGs.
"""

ALLOWED_ELEMENTS = {
    # Structure
    "svg", "g", "defs", "symbol", "use", "switch", "view", "a", "title", "desc", "metadata",
    # Shapes
    "path", "rect", "circle", "ellipse", "line", "polyline", "polygon",
    # Text
    "text", "tspan", "textPath", "tref", "altGlyph",
    # Paint
    "linearGradient", "radialGradient", "stop", "pattern", "mask", "clipPath", "marker", "image",
    # Filters
    "filter", "feBlend", "feColorMatrix", "feComponentTransfer", "feComposite",
    "feConvolveMatrix", "feDiffuseLighting", "feDisplacementMap", "feFlood",
    "feGaussianBlur", "feImage", "feMerge", "feMergeNode", "feMorphology",
    "feOffset", "feSpecularLighting", "feTile", "feTurbulence",
    "feDistantLight", "fePointLight", "feSpotLight",
    "feFuncR", "feFuncG", "feFuncB", "feFuncA",
    # Animation
    "animate", "animateTransform", "animateMotion", "set", "mpath",
    # Fonts
    "font", "font-face", "font-face-src", "font-face-uri", "font-face-format",
    "font-face-name", "glyph", "missing-glyph", "hkern", "vkern",
    # Style
    "style",
}

# Hard-blocked — these are how XSS gets in
DISALLOWED_ELEMENTS = {
    "script", "foreignObject", "iframe", "object", "embed", "handler",
}

# Any attribute starting with "on" is an event handler — always strip
EVENT_HANDLER_PREFIX = "on"

# Strict URL allow-list for href / xlink:href
SAFE_URL_PREFIXES = ("#", "http://", "https://", "data:image/")

# Style values that smuggle JS
DANGEROUS_STYLE_PATTERNS = ("expression(", "javascript:", "vbscript:", "@import")