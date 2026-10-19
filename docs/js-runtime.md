# JS Runtime

## Overview
The JS runtime in `src/js/` has two layers:

1. **Static analysis** (`analysis.rs`) — parses JS with `oxc_parser`, walks the AST,
   and extracts dangerous patterns without executing anything.
2. **Sandboxed execution** (`runtime.rs`) — used only when a framework is detected.
   Runs JS inside `rquickjs` (QuickJS binding) with a virtual DOM injected as the
   global `document`/`window`. No real network, filesystem, or timer access.

## Static Analysis (`analysis.rs`)

### What It Detects
| Pattern | Detection Method |
|---------|-----------------|
| `eval(...)` / `Function(...)` | Call expression callee matching |
| `document.write(...)` | Member-call pattern |
| `innerHTML =` / `outerHTML =` | Assignment to known XSS sinks |
| `fetch(...)` / `XMLHttpRequest` | Call + constructor detection |
| `window.location = ...` | Assignment to redirect sink |
| `document.cookie` access | Member expression |
| `atob(...)` / `btoa(...)` | Base64 obfuscation detection |
| Hex string literals `\x41\x42...` | String literal pattern scan |
| `setTimeout/setInterval` with string | String-as-code execution |
| Dynamic `import()` | Import expression |
| `postMessage` | Cross-origin communication |
| `WebSocket` constructor | Network attempt |

### Output
`StaticAnalysisReport`:
```rust
pub struct StaticAnalysisReport {
    pub eval_calls: Vec<CodeLocation>,
    pub dom_mutations: Vec<DomMutation>,
    pub network_calls: Vec<NetworkCall>,
    pub redirect_attempts: Vec<String>,
    pub decoded_strings: Vec<DecodedString>,
    pub obfuscation_score: u8,   // 0–100
}
```

## Sandboxed Runtime (`runtime.rs`)

### When It Runs
Only when `FrameworkDetector` identifies React, Vue, Angular, Svelte, Next.js,
or Nuxt. Plain HTML pages use static analysis only.

### Sandbox Globals
| Global | Behaviour |
|--------|-----------|
| `document` | Virtual DOM (see `vdom.rs`) |
| `window` | Proxied to `document`; `location`, `navigator` stubbed |
| `fetch` | Always returns `Promise.reject(new Error("blocked"))` + logs attempt |
| `XMLHttpRequest` | Constructor returns non-functional stub + logs |
| `WebSocket` | Constructor throws + logs |
| `localStorage` | In-memory store (cleared after run) |
| `sessionStorage` | In-memory store (cleared after run) |
| `console.log/warn/error` | Captured into `ThreatReport.console_output` |
| `setTimeout/setInterval` | Scheduled but capped at 100ms total run time |
| `crypto.getRandomValues` | Returns deterministic bytes (seeded 0) |
| `performance.now` | Returns monotonically increasing fake timestamps |
| `requestAnimationFrame` | Calls callback once synchronously |

### Execution Flow
1. Build `rquickjs::Runtime` with memory limit (default 64 MB).
2. Create `rquickjs::Context`.
3. Inject virtual DOM globals into context.
4. Evaluate each collected inline `<script>` block in order.
5. Call `document.__snapshot__()` to extract the virtual DOM tree.
6. Serialize snapshot to `DomSnapshot`.
7. Drop context + runtime (QuickJS heap freed).

### Resource Limits
| Resource | Limit |
|----------|-------|
| Heap memory | 64 MB |
| CPU time | 5 seconds (interrupt after deadline) |
| Script count | 20 scripts per page |
| Recursion depth | 512 |

### What Is NOT Available
- File system access
- Native modules
- Timers beyond capped budget
- Network (all intercepted)
- `process` / Node.js globals
- Browser APIs beyond the virtual DOM surface

## Framework Detection
Detection happens in `html/mod.rs` before the JS runtime is invoked.

| Signal | Framework |
|--------|-----------|
| `<div id="root">` + `react` in script src | React |
| `window.__NUXT__` global | Nuxt |
| `ng-version` attribute | Angular |
| `data-v-*` attributes | Vue |
| `__svelte*` globals | Svelte |
| `_next/static` in script src | Next.js |
