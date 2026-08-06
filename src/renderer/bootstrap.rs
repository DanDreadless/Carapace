//! Render-time bootstrap scripts, split so the two render paths can share the
//! parts that apply to both while differing on network handling (CARAPACE-09 P0-b,
//! Phase 2).
//!
//! * [`IDENTITY_NAV_BOOTSTRAP`] — spoof a Windows identity (so OS-gated
//!   ClickFix/SocGholish payloads execute and become visible), suppress
//!   navigation and `<meta http-equiv="refresh">` (so a timed/scripted redirect
//!   can't escape before the screenshot), and remove loading-screen overlays for
//!   a clean capture. Applies to **both** paths. On the CDP live path it is
//!   injected via `Page.addScriptToEvaluateOnNewDocument`; on the offline
//!   `file://` path it is prepended to the self-contained HTML.
//! * [`OFFLINE_NETWORK_MOCK`] — replace `fetch`/`XMLHttpRequest` with an
//!   immediate empty `{}` 200 so a data-driven SPA renders *something* when all
//!   network is refused. **Offline path only.** The live path must NOT use it: it
//!   loads real same-origin content through the SSRF `PolicyProxy`, which is the
//!   whole point of the live render.

/// Windows-identity spoof + navigation/refresh suppression + loader-overlay
/// killer. Shared by the offline and CDP live render paths.
pub const IDENTITY_NAV_BOOTSTRAP: &str = r#"
(function() {
  try {
    Object.defineProperty(navigator, 'platform',    {get: function() { return 'Win32'; }});
    Object.defineProperty(navigator, 'oscpu',       {get: function() { return 'Windows NT 10.0; Win64; x64'; }});
    Object.defineProperty(navigator, 'appVersion',  {get: function() { return '5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36'; }});
  } catch(e) {}
  // Suppress navigation so overlays render fully before the screenshot is taken.
  try {
    window.location.replace = function() {};
    window.location.assign  = function() {};
    window.location.reload  = function() {};
  } catch(e) {}
  try {
    var _d = Object.getOwnPropertyDescriptor(Location.prototype, 'href');
    if (_d) {
      Object.defineProperty(Location.prototype, 'href', {
        get: _d.get,
        set: function() {},
        configurable: true
      });
    }
  } catch(e) {}
  // Neutralise <meta http-equiv="refresh"> so a timed redirect cannot escape
  // capture (this script runs at document-start, before the meta may exist, so
  // also sweep on DOMContentLoaded).
  try {
    var _stripRefresh = function() {
      try {
        document.querySelectorAll('meta[http-equiv]').forEach(function(m) {
          if (/refresh/i.test(m.getAttribute('http-equiv') || '')) m.remove();
        });
      } catch(ex) {}
    };
    _stripRefresh();
    document.addEventListener('DOMContentLoaded', _stripRefresh, {once:true});
  } catch(e) {}
  // Loader-screen killer — MutationObserver fires synchronously on every DOM
  // mutation so it does NOT depend on virtual-time advancing (unlike setTimeout).
  // When Vue/React mounts and creates #app-loading, the observer fires immediately
  // in the same microtask checkpoint and removes it before the next paint.
  //
  // Two strategies are combined:
  //   1. Named-selector kill: targets IDs/classes used by common phishing kits.
  //   2. Appearance-based kill: removes ANY fullscreen white/near-white fixed
  //      overlay regardless of what name the kit chose, by checking computed
  //      position, size, and background colour.
  function _killLoaders() {
    try {
      var sel = '#app-loading,#loading,#preloader,#loader,#splash,#page-loader,' +
                '[id*="loading"],[id*="preloader"],[id*="spinner"],[id*="splash"],' +
                '[class*="app-loading"],[class*="loading-screen"],[class*="page-loader"],' +
                '[class*="preloader"],[class*="spinner"]';
      document.querySelectorAll(sel).forEach(function(el) {
        try {
          el.style.setProperty('display',     'none',   'important');
          el.style.setProperty('visibility',  'hidden', 'important');
          el.remove();
        } catch(ex) {}
      });
      document.querySelectorAll('div,section,main,aside,header,footer').forEach(function(el) {
        try {
          var cs = window.getComputedStyle(el);
          if (cs.position !== 'fixed' && cs.position !== 'absolute') return;
          var r = el.getBoundingClientRect();
          if (!r || r.width < window.innerWidth * 0.8 || r.height < window.innerHeight * 0.8) return;
          var m = cs.backgroundColor.match(/rgba?\((\d+),\s*(\d+),\s*(\d+)/);
          if (m && +m[1] >= 230 && +m[2] >= 230 && +m[3] >= 230) {
            el.style.setProperty('display', 'none', 'important');
            el.remove();
          }
        } catch(ex) {}
      });
    } catch(e) {}
  }
  try {
    var _obs = new MutationObserver(function() { _killLoaders(); });
    _obs.observe(document.documentElement || document, {
      childList: true, subtree: true,
      attributes: true, attributeFilter: ['style','class','id']
    });
  } catch(e) {}
  try { document.addEventListener('DOMContentLoaded', _killLoaders, {once:true}); } catch(e) {}
  try { requestAnimationFrame(_killLoaders); } catch(e) {}
})();
"#;

/// `fetch`/`XMLHttpRequest` -> immediate empty `{}` 200. **Offline path only** —
/// never inject on the live path (it would blind the render to real same-origin
/// content fetched through the SSRF proxy).
pub const OFFLINE_NETWORK_MOCK: &str = r#"
(function() {
  try {
    window.fetch = function(url, opts) {
      return Promise.resolve(new Response('{}', {
        status: 200,
        headers: {'Content-Type': 'application/json'}
      }));
    };
  } catch(e) {}
  try {
    window.XMLHttpRequest = function() {
      var self = this;
      self.open = function() {};
      self.setRequestHeader = function() {};
      self.send = function() {
        var me = self;
        setTimeout(function() {
          Object.defineProperty(me, 'readyState',   {get: function(){return 4;}});
          Object.defineProperty(me, 'status',       {get: function(){return 200;}});
          Object.defineProperty(me, 'responseText', {get: function(){return '{}';}});
          Object.defineProperty(me, 'response',     {get: function(){return '{}';}});
          if (me.onreadystatechange) me.onreadystatechange();
          if (me.onload) me.onload();
        }, 0);
      };
    };
  } catch(e) {}
})();
"#;

/// The full offline-path bootstrap: identity/nav/loader handling **plus** the
/// network mock, in that order — behaviourally identical to the previous single
/// `WINDOWS_BOOTSTRAP` blob.
pub fn offline_bootstrap() -> String {
    format!("{IDENTITY_NAV_BOOTSTRAP}\n{OFFLINE_NETWORK_MOCK}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_nav_has_shared_parts_but_not_the_network_mock() {
        assert!(IDENTITY_NAV_BOOTSTRAP.contains("'Win32'"), "spoofs platform");
        assert!(IDENTITY_NAV_BOOTSTRAP.contains("location.replace"), "suppresses navigation");
        assert!(IDENTITY_NAV_BOOTSTRAP.contains("http-equiv"), "neutralises meta refresh");
        assert!(IDENTITY_NAV_BOOTSTRAP.contains("_killLoaders"), "kills loader overlays");
        // The live path must keep real fetch: the shared part carries no mock.
        assert!(!IDENTITY_NAV_BOOTSTRAP.contains("window.fetch = function"), "no fetch mock in shared part");
        assert!(!IDENTITY_NAV_BOOTSTRAP.contains("window.XMLHttpRequest = function"), "no XHR mock in shared part");
    }

    #[test]
    fn network_mock_is_only_the_mock() {
        assert!(OFFLINE_NETWORK_MOCK.contains("window.fetch = function"));
        assert!(OFFLINE_NETWORK_MOCK.contains("window.XMLHttpRequest = function"));
        assert!(!OFFLINE_NETWORK_MOCK.contains("'Win32'"), "identity lives in the shared part");
    }

    #[test]
    fn offline_bootstrap_is_the_union() {
        let full = offline_bootstrap();
        assert!(full.contains("'Win32'") && full.contains("window.fetch = function"));
    }
}
