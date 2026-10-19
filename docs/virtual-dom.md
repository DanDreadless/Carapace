# Virtual DOM

## Overview
`src/js/vdom.rs` implements a minimal DOM tree in Rust and exposes it to the
rquickjs sandbox as the `document` and `window` globals.

Frameworks call standard DOM APIs; Carapace records the mutations but never
touches a real browser DOM.

## Rust Data Model

```rust
pub struct VDom {
    nodes: Vec<VNode>,           // arena-style storage
    root: NodeId,                // document root
    body: NodeId,
    head: NodeId,
}

pub struct VNode {
    pub id: NodeId,
    pub kind: VNodeKind,
    pub parent: Option<NodeId>,
    pub children: Vec<NodeId>,
    pub attrs: IndexMap<String, String>,
    pub style: IndexMap<String, String>,
    pub text: Option<String>,
    pub event_listeners: Vec<EventListener>, // collected but never fired
}

pub enum VNodeKind {
    Document,
    Element(String),  // tag name
    Text,
    Comment,
}
```

## JS-Visible API

### `document`
| Method/Property | Behaviour |
|----------------|-----------|
| `document.createElement(tag)` | Creates VNode, returns JS proxy |
| `document.createTextNode(text)` | Creates text VNode |
| `document.createComment(text)` | Creates comment VNode |
| `document.createDocumentFragment()` | Returns detached container |
| `document.getElementById(id)` | Searches VDom by id attribute |
| `document.getElementsByTagName(tag)` | Returns array of matching nodes |
| `document.getElementsByClassName(cls)` | Returns array of matching nodes |
| `document.querySelector(sel)` | Simple CSS selector (tag, .class, #id) |
| `document.querySelectorAll(sel)` | Returns array |
| `document.body` | Returns body VNode proxy |
| `document.head` | Returns head VNode proxy |
| `document.documentElement` | Returns html VNode proxy |
| `document.title` | Get/set via head > title element |
| `document.cookie` | Getter returns `""`; setter logged as threat |
| `document.write(html)` | Parses and appends; logged as medium-risk |
| `document.addEventListener` | No-op (events never fire) |
| `document.__snapshot__()` | Carapace internal — serialises VDom to JSON |

### Element nodes
| Method/Property | Behaviour |
|----------------|-----------|
| `el.appendChild(child)` | Reparents child in VDom |
| `el.insertBefore(new, ref)` | Inserts before ref node |
| `el.removeChild(child)` | Detaches from VDom |
| `el.replaceChild(new, old)` | Swap in VDom |
| `el.cloneNode(deep)` | Deep-copies VNode subtree |
| `el.setAttribute(name, value)` | Sanitized: blocked if `on*` or JS URL |
| `el.getAttribute(name)` | Returns attr value or null |
| `el.removeAttribute(name)` | Removes from attr map |
| `el.hasAttribute(name)` | Bool check |
| `el.innerHTML` setter | Parses HTML fragment; sanitizer applied |
| `el.innerHTML` getter | Serialises VNode subtree to HTML string |
| `el.textContent` setter | Sets text node |
| `el.textContent` getter | Concatenates text descendants |
| `el.style.setProperty(k, v)` | Updates inline style map |
| `el.style[prop]` | Get/set via camelCase property name |
| `el.classList.add/remove/toggle` | Updates class attribute |
| `el.addEventListener(ev, fn)` | Recorded in `event_listeners`; never fires |
| `el.dispatchEvent` | No-op |
| `el.getBoundingClientRect()` | Returns `{top:0,left:0,width:0,height:0,...}` |
| `el.offsetWidth/Height` | Returns 0 (layout not computed at this stage) |

### `window`
| Property/Method | Behaviour |
|----------------|-----------|
| `window.document` | Alias to `document` |
| `window.location` | Stub: `href` = original URL; assignment logged as redirect |
| `window.navigator.userAgent` | Returns `"Carapace/0.1"` |
| `window.navigator.language` | Returns `"en-US"` |
| `window.history` | No-op stub |
| `window.screen` | Returns `{width:1280, height:800}` |
| `window.innerWidth/Height` | Returns `1280` / `800` |
| `window.addEventListener` | Recorded; never fires |
| `window.dispatchEvent` | No-op |
| `window.getComputedStyle(el)` | Returns empty CSSStyleDeclaration |
| `window.atob(s)` | Decodes base64; result added to `decoded_strings` in threat report |
| `window.btoa(s)` | Encodes; no-op for threat purposes |

## Snapshot Output (`__snapshot__`)
The virtual DOM is serialised to the `DomSnapshot` struct which feeds the layout engine:

```json
{
  "tag": "html",
  "attrs": { "lang": "en" },
  "style": {},
  "children": [
    {
      "tag": "body",
      "attrs": {},
      "style": { "margin": "0" },
      "children": [ ... ]
    }
  ]
}
```
