# HTML Sanitizer

## Overview
`src/html/sanitizer.rs` walks the parsed `html5ever` RcDom and removes or
neutralises all content that could execute code or exfiltrate data.

The sanitizer operates on an **allowlist** model: only known-safe elements are
kept. Unknown or dangerous elements are stripped (children are preserved unless
the element is a script/style/meta-redirect).

## Element Handling

### Completely Removed (no children kept)
| Element | Reason |
|---------|--------|
| `<script>` | JS execution |
| `<noscript>` | May contain hidden markup |
| `<iframe>` | Embedded document |
| `<frame>`, `<frameset>` | Legacy embedded docs |
| `<object>`, `<embed>` | Plugin execution |
| `<applet>` | Legacy Java |
| `<base>` | Can redirect all relative URLs |

### Stripped (children kept)
Any element not in the allowlist is replaced with its children.
The element tag is recorded in the threat report as `BlockedElement`.

### Allowed Elements (partial list)
`a`, `abbr`, `address`, `article`, `aside`, `b`, `blockquote`, `br`,
`caption`, `cite`, `code`, `col`, `colgroup`, `dd`, `del`, `details`,
`dfn`, `div`, `dl`, `dt`, `em`, `figcaption`, `figure`, `footer`,
`h1`–`h6`, `header`, `hr`, `i`, `img`, `ins`, `kbd`, `li`, `main`,
`mark`, `nav`, `ol`, `p`, `picture`, `pre`, `q`, `s`, `section`,
`small`, `source`, `span`, `strong`, `sub`, `summary`, `sup`,
`table`, `tbody`, `td`, `tfoot`, `th`, `thead`, `time`, `tr`, `u`,
`ul`, `var`, `video` (controls only, no autoplay), `wbr`

## Attribute Handling

### Blocked Attribute Patterns
| Pattern | Example | Action |
|---------|---------|--------|
| `on*` | `onclick`, `onload`, `onerror` | Removed; event logged |
| `href` with `javascript:` | `href="javascript:void(0)"` | Removed; logged |
| `src` with `javascript:` | `src="javascript:..."` | Removed; logged |
| `src` with `data:` | `data:text/html,...` | Removed; logged |
| `href` with `data:` | `data:text/html,...` | Removed; logged |
| `action` with `javascript:` | form action | Removed; logged |
| `formaction` | any | Removed (prevents form hijack) |
| `xlink:href` with `javascript:` | SVG | Removed; logged |
| `srcdoc` | iframe srcdoc | Removed (iframe already blocked) |

### Preserved Attributes (element-specific)
- `href` — scheme must be `http`, `https`, `mailto`, `tel`, `#`
- `src` — scheme must be `http`, `https`; `data:image/*` allowed for images
- `alt`, `title`, `aria-*`, `role` — always safe
- `class`, `id` — kept (needed for CSS/layout)
- `style` — CSS parsed and sanitized (no `expression()`, `url(javascript:)`, `-moz-binding`)

## `<meta>` Handling
- `<meta http-equiv="refresh">` — stripped (redirect/delay attacks)
- `<meta http-equiv="Content-Security-Policy">` — stripped (attacker setting their own CSP)
- `<meta name="*">` description/keywords/viewport — kept

## `<link>` Handling
- `rel="stylesheet"` — href collected for CSS fetching (goes through SafeFetcher)
- `rel="preload"`, `rel="prefetch"` — stripped (prevents side-channel timing)
- `rel="import"` — stripped

## Threat Report Integration
Each removal is appended to the `ThreatReport`:
```json
{
  "blocked_elements": ["script", "iframe"],
  "blocked_attributes": [
    { "element": "a", "attr": "onclick", "value": "steal()" },
    { "element": "img", "attr": "src", "value": "javascript:..." }
  ]
}
```

## Known Bypass Research
- SVG `<animate>` with `href` — monitor for JS-trigger patterns
- CSS `@import` of external sheets — always fetched through SafeFetcher
- HTML entities in `href` — url crate normalises before scheme check
- Null-byte injection in attribute values — stripped by html5ever tokeniser
- UTF-7 / charset tricks — encoding_rs normalises to UTF-8 before parse
