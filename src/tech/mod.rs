//! Technology stack detection from a parsed HTML document.
//!
//! Analyses the fully-parsed DOM, script/stylesheet resource URLs, inline
//! script content, CSS class tokens, and `<meta>` generator tags to produce
//! a list of detected technologies.
//!
//! Every detection uses one of two confidence levels:
//!   - **high**   — unambiguous (meta generator tag, version-in-attribute, CMS path prefix)
//!   - **medium** — strong indicator (CDN URL pattern, CSS class fingerprint, inline string)
//!
//! No external API calls are made; all detection is offline and content-based.

use markup5ever_rcdom::{Handle, NodeData};
use serde::{Deserialize, Serialize};
use tracing::debug;
use url::Url;

// ── Public types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TechDetection {
    pub name: String,
    pub category: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// `"high"` or `"medium"`
    pub confidence: String,
}

impl TechDetection {
    fn high(name: &str, category: &str, version: Option<String>) -> Self {
        Self { name: name.into(), category: category.into(), version, confidence: "high".into() }
    }
    fn medium(name: &str, category: &str, version: Option<String>) -> Self {
        Self { name: name.into(), category: category.into(), version, confidence: "medium".into() }
    }
}

// ── Entry point ───────────────────────────────────────────────────────────────

/// Run tech-stack detection and return every technology found.
///
/// Must be called on the **pre-sanitisation** DOM — the sanitiser removes
/// custom elements and non-standard attributes (e.g. `ng-version`, `hx-*`)
/// that carry framework fingerprints.
pub fn detect(
    document: &Handle,
    script_urls: &[Url],
    inline_scripts: &[String],
    stylesheet_urls: &[Url],
) -> Vec<TechDetection> {
    let mut out: Vec<TechDetection> = Vec::new();

    // Collect DOM-level signals in a single pass.
    let mut dom = DomSignals::default();
    walk_dom(document, &mut dom);

    check_meta_generators(&dom, &mut out);
    check_dom_attributes(&dom, &mut out);
    check_css_classes(&dom, &mut out);
    check_script_urls(script_urls, &mut out);
    check_stylesheet_urls(stylesheet_urls, &mut out);
    check_inline_scripts(inline_scripts, &mut out);
    check_cms_paths(&dom, script_urls, stylesheet_urls, &mut out);

    // Deduplicate by name (keep first occurrence — highest-confidence checks run first).
    out.dedup_by(|a, b| a.name == b.name);

    debug!("tech_detector: found {} technologies", out.len());
    out
}

// ── DOM signal collection ─────────────────────────────────────────────────────

/// Signals extracted from a single DOM walk shared by all checks.
#[derive(Default)]
struct DomSignals {
    /// All attribute name→value pairs seen across the whole document.
    attrs: Vec<(String, String)>,
    /// All unique CSS class tokens seen across the whole document.
    classes: Vec<String>,
    /// All meta tag `name`→`content` pairs.
    meta: Vec<(String, String)>,
    /// All href values from <a> and <link> tags, and src values from <script>/<img>.
    paths: Vec<String>,
    /// Concatenated text content of all inline <script> blocks.
    inline_js: String,
}

fn walk_dom(handle: &Handle, signals: &mut DomSignals) {
    if let NodeData::Element { name, attrs, .. } = &handle.data {
        let tag = name.local.as_ref().to_ascii_lowercase();
        let attrs_ref = attrs.borrow();

        // Collect all attributes.
        for attr in attrs_ref.iter() {
            let key = attr.name.local.as_ref().to_ascii_lowercase();
            let val = attr.value.as_ref().to_string();

            if key == "class" {
                for tok in val.split_whitespace() {
                    let t = tok.to_string();
                    if !signals.classes.contains(&t) {
                        signals.classes.push(t);
                    }
                }
            }

            signals.attrs.push((key.clone(), val.clone()));

            if key == "src" || key == "href" {
                signals.paths.push(val);
            }
        }

        // Collect meta generator tags.
        if tag == "meta" {
            let meta_name = attrs_ref.iter()
                .find(|a| a.name.local.as_ref().eq_ignore_ascii_case("name"))
                .map(|a| a.value.as_ref().to_ascii_lowercase())
                .unwrap_or_default();
            let content = attrs_ref.iter()
                .find(|a| a.name.local.as_ref().eq_ignore_ascii_case("content"))
                .map(|a| a.value.as_ref().to_string())
                .unwrap_or_default();
            if !meta_name.is_empty() && !content.is_empty() {
                signals.meta.push((meta_name, content));
            }
        }

        // Collect inline script text.
        if tag == "script" {
            let has_src = attrs_ref.iter().any(|a| a.name.local.as_ref().eq_ignore_ascii_case("src"));
            if !has_src {
                signals.inline_js.push_str(&collect_text(handle));
                signals.inline_js.push('\n');
            }
        }
    }

    for child in handle.children.borrow().iter() {
        walk_dom(child, signals);
    }
}

fn collect_text(handle: &Handle) -> String {
    let mut buf = String::new();
    collect_text_inner(handle, &mut buf);
    buf
}
fn collect_text_inner(handle: &Handle, buf: &mut String) {
    if let NodeData::Text { contents } = &handle.data {
        buf.push_str(contents.borrow().as_ref());
    }
    for child in handle.children.borrow().iter() {
        collect_text_inner(child, buf);
    }
}

// ── Detection checks ──────────────────────────────────────────────────────────

fn check_meta_generators(dom: &DomSignals, out: &mut Vec<TechDetection>) {
    for (name, content) in &dom.meta {
        if name != "generator" {
            continue;
        }
        let cl = content.to_ascii_lowercase();

        let rules: &[(&str, &str)] = &[
            ("wordpress", "WordPress"),
            ("drupal",    "Drupal"),
            ("joomla",    "Joomla"),
            ("ghost",     "Ghost"),
            ("hugo",      "Hugo"),
            ("jekyll",    "Jekyll"),
            ("gatsby",    "Gatsby"),
            ("eleventy",  "Eleventy"),
            ("webflow",   "Webflow"),
            ("squarespace", "Squarespace"),
            ("wix.com",   "Wix"),
            ("shopify",   "Shopify"),
            ("magento",   "Magento"),
        ];
        for (needle, tech_name) in rules {
            if cl.contains(needle) {
                let version = extract_version(content);
                add(out, TechDetection::high(tech_name, "CMS", version));
                break;
            }
        }
    }
}

fn check_dom_attributes(dom: &DomSignals, out: &mut Vec<TechDetection>) {
    let has_attr = |name: &str| dom.attrs.iter().any(|(k, _)| k == name);
    let attr_value = |name: &str| -> Option<&str> {
        dom.attrs.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    };
    let has_attr_prefix = |prefix: &str| dom.attrs.iter().any(|(k, _)| k.starts_with(prefix));

    // Angular — ng-version attribute carries the version string.
    if let Some(ver) = attr_value("ng-version") {
        add(out, TechDetection::high("Angular", "JavaScript Framework", Some(ver.to_string())));
    } else if has_attr_prefix("_nghost") || has_attr_prefix("_ngcontent") {
        add(out, TechDetection::high("Angular", "JavaScript Framework", None));
    }

    // Vue — scoped style hashes (data-v-XXXXXXXX) or v-cloak.
    if has_attr_prefix("data-v-") || has_attr("v-cloak") {
        add(out, TechDetection::high("Vue", "JavaScript Framework", None));
    }

    // React — data-reactroot / data-reactid.
    if has_attr("data-reactroot") || has_attr("data-reactid") {
        add(out, TechDetection::high("React", "JavaScript Framework", None));
    }

    // Svelte — data-svelte-h attribute on hydrated elements.
    if has_attr_prefix("data-svelte") || has_attr("svelte-retarget") {
        add(out, TechDetection::high("Svelte", "JavaScript Framework", None));
    }

    // htmx — presence of any hx-* attribute.
    if has_attr_prefix("hx-") {
        add(out, TechDetection::medium("htmx", "JavaScript Library", None));
    }

    // Alpine.js — x-data / x-bind / x-on / x-show / x-text.
    if dom.attrs.iter().any(|(k, _)| k.starts_with("x-") || k == "@click" || k.starts_with(":")) {
        // Be precise — x-data is definitively Alpine.
        if has_attr_prefix("x-data") || has_attr_prefix("x-show") || has_attr_prefix("x-bind") {
            add(out, TechDetection::medium("Alpine.js", "JavaScript Framework", None));
        }
    }

    // Stimulus (Hotwire) — data-controller attribute.
    if has_attr("data-controller") && has_attr_prefix("data-action") {
        add(out, TechDetection::medium("Stimulus", "JavaScript Framework", None));
    }

    // Turbo (Hotwire) — data-turbo attributes.
    if has_attr_prefix("data-turbo") {
        add(out, TechDetection::medium("Turbo", "JavaScript Library", None));
    }

    // HTMX boost.
    if has_attr("hx-boost") {
        add(out, TechDetection::medium("htmx", "JavaScript Library", None));
    }

    // Livewire (Laravel) — wire:id or wire:data.
    if has_attr_prefix("wire:") {
        add(out, TechDetection::high("Livewire", "JavaScript Framework", None));
    }

    // Inertia.js — data-page attribute.
    if has_attr("data-page") && dom.attrs.iter().any(|(k, v)| k == "data-page" && v.contains("component")) {
        add(out, TechDetection::medium("Inertia.js", "JavaScript Framework", None));
    }
}

fn check_css_classes(dom: &DomSignals, out: &mut Vec<TechDetection>) {
    let classes = &dom.classes;

    // Tailwind CSS — look for responsive or variant prefixes.
    // sm:/md:/lg:/xl:/2xl: responsive breakpoints are uniquely Tailwind.
    // hover:/focus:/dark:/group- variant prefixes also specific to Tailwind.
    let tailwind_prefixes = ["sm:", "md:", "lg:", "xl:", "2xl:", "hover:", "focus:", "dark:", "group-", "peer-"];
    let tailwind_hits = classes.iter().filter(|c| tailwind_prefixes.iter().any(|p| c.starts_with(p))).count();
    if tailwind_hits >= 2 {
        add(out, TechDetection::medium("Tailwind CSS", "CSS Framework", None));
    }

    // Bootstrap — column grid classes (col-sm-*, col-md-*, col-lg-*) are Bootstrap-specific.
    let bootstrap_grid = classes.iter().filter(|c| {
        let c = c.as_str();
        c.starts_with("col-sm-") || c.starts_with("col-md-") || c.starts_with("col-lg-")
        || c.starts_with("col-xl-") || c == "container-fluid" || c == "row"
    }).count();
    // btn-* classes are Bootstrap-specific.
    let bootstrap_btn = classes.iter().any(|c| {
        c.as_str() == "btn-primary" || c.as_str() == "btn-secondary" || c.as_str() == "btn-success"
        || c.as_str() == "btn-danger" || c.as_str() == "btn-warning"
    });
    if bootstrap_grid >= 2 || (bootstrap_grid >= 1 && bootstrap_btn) {
        add(out, TechDetection::medium("Bootstrap", "CSS Framework", None));
    }

    // Bulma — is-* utility classes + column/hero/button structure.
    let bulma_hits = classes.iter().filter(|c| {
        c.starts_with("is-") || c.starts_with("has-") || c.as_str() == "columns" || c.as_str() == "hero"
    }).count();
    if bulma_hits >= 3 {
        add(out, TechDetection::medium("Bulma", "CSS Framework", None));
    }

    // Foundation — columns float-* classes.
    let foundation_hits = classes.iter().filter(|c| {
        c.starts_with("small-") || c.starts_with("medium-") || c.starts_with("large-")
    }).count();
    if foundation_hits >= 2 && classes.iter().any(|c| c == "callout" || c == "off-canvas") {
        add(out, TechDetection::medium("Foundation", "CSS Framework", None));
    }

    // Materialize CSS — materialize-specific classes.
    if classes.iter().any(|c| c == "materialize-textarea" || c == "waves-effect" || c == "z-depth-1") {
        add(out, TechDetection::medium("Materialize CSS", "CSS Framework", None));
    }

    // shadcn/ui — uses specific data-state and ring-offset utility patterns alongside Tailwind.
    let shadcn_hits = classes.iter().filter(|c| {
        c.starts_with("ring-offset") || c.starts_with("focus-visible:ring") || c.as_str() == "inline-flex"
    }).count();
    if shadcn_hits >= 2 && tailwind_hits >= 2 {
        add(out, TechDetection::medium("shadcn/ui", "UI Library", None));
    }
}

fn check_script_urls(script_urls: &[Url], out: &mut Vec<TechDetection>) {
    for url in script_urls {
        let path = url.path().to_ascii_lowercase();
        let host = url.host_str().unwrap_or("").to_ascii_lowercase();
        let full = format!("{}{}", host, path);

        let rules: &[(&str, &str, &str)] = &[
            // JS Frameworks
            ("react-dom",          "React",          "JavaScript Framework"),
            ("react.min",          "React",          "JavaScript Framework"),
            ("react.production",   "React",          "JavaScript Framework"),
            ("/vue@",              "Vue",            "JavaScript Framework"),
            ("/vue.min",           "Vue",            "JavaScript Framework"),
            ("/vue.esm",           "Vue",            "JavaScript Framework"),
            ("@vue/",              "Vue",            "JavaScript Framework"),
            ("angular.min",        "Angular",        "JavaScript Framework"),
            ("@angular/",          "Angular",        "JavaScript Framework"),
            ("/svelte/",           "Svelte",         "JavaScript Framework"),
            ("/svelte@",           "Svelte",         "JavaScript Framework"),
            ("alpinejs",           "Alpine.js",      "JavaScript Framework"),
            ("/htmx",              "htmx",           "JavaScript Library"),
            ("preact",             "Preact",         "JavaScript Framework"),
            ("/solid-js",          "SolidJS",        "JavaScript Framework"),
            ("/ember.",            "Ember.js",       "JavaScript Framework"),
            ("/backbone.",         "Backbone.js",    "JavaScript Library"),
            ("stimulus",           "Stimulus",       "JavaScript Framework"),
            ("/lit/",              "Lit",            "JavaScript Framework"),
            ("/lit@",              "Lit",            "JavaScript Framework"),
            ("/mithril",           "Mithril",        "JavaScript Framework"),
            // Libraries
            ("/jquery",            "jQuery",         "JavaScript Library"),
            ("jquery.min",         "jQuery",         "JavaScript Library"),
            ("/lodash",            "Lodash",         "JavaScript Library"),
            ("/underscore",        "Underscore.js",  "JavaScript Library"),
            ("/moment",            "Moment.js",      "JavaScript Library"),
            ("/three.",            "Three.js",       "JavaScript Library"),
            ("chart.min",          "Chart.js",       "JavaScript Library"),
            ("chart.umd",          "Chart.js",       "JavaScript Library"),
            ("/d3.min",            "D3.js",          "JavaScript Library"),
            ("/d3@",               "D3.js",          "JavaScript Library"),
            ("socket.io",          "Socket.IO",      "JavaScript Library"),
            ("gsap",               "GSAP",           "JavaScript Library"),
            // Meta frameworks (URL path patterns)
            ("/_next/static",      "Next.js",        "Meta Framework"),
            ("/_nuxt/",            "Nuxt",           "Meta Framework"),
            ("/gatsby-",           "Gatsby",         "Meta Framework"),
            ("/remix-",            "Remix",          "Meta Framework"),
            ("/__sveltekit",       "SvelteKit",      "Meta Framework"),
            ("/.svelte-kit",       "SvelteKit",      "Meta Framework"),
            // Analytics & tracking
            ("googletagmanager",   "Google Tag Manager", "Analytics"),
            ("google-analytics",   "Google Analytics",   "Analytics"),
            ("/analytics.js",      "Google Analytics",   "Analytics"),
            ("/gtag/js",           "Google Analytics",   "Analytics"),
            ("plausible.io",       "Plausible",      "Analytics"),
            ("matomo.js",          "Matomo",         "Analytics"),
            ("piwik.js",           "Matomo",         "Analytics"),
            ("hotjar",             "Hotjar",         "Analytics"),
            ("clarity.ms",         "Microsoft Clarity", "Analytics"),
            ("segment.com",        "Segment",        "Analytics"),
            ("mixpanel",           "Mixpanel",       "Analytics"),
            ("fullstory",          "FullStory",      "Analytics"),
            // Security / verification
            ("recaptcha",          "Google reCAPTCHA",  "Security"),
            ("hcaptcha",           "hCaptcha",           "Security"),
            ("challenges.cloudflare", "Cloudflare Turnstile", "Security"),
            // CDNs
            ("cdnjs.cloudflare",   "cdnjs",          "CDN"),
            ("cdn.jsdelivr",       "jsDelivr",       "CDN"),
            ("unpkg.com",          "unpkg",          "CDN"),
            ("ajax.googleapis",    "Google Hosted Libraries", "CDN"),
            // Payment
            ("js.stripe",          "Stripe",         "Payment"),
            ("checkout.stripe",    "Stripe",         "Payment"),
            ("paypal",             "PayPal",         "Payment"),
            // Customer support
            ("intercom",           "Intercom",       "Customer Support"),
            ("zopim",              "Zendesk Chat",   "Customer Support"),
            ("zendesk",            "Zendesk",        "Customer Support"),
        ];

        for (needle, name, category) in rules {
            if full.contains(needle) {
                let version = extract_version_from_url(&full);
                add(out, TechDetection::medium(name, category, version));
                break;
            }
        }
    }
}

fn check_stylesheet_urls(stylesheet_urls: &[Url], out: &mut Vec<TechDetection>) {
    for url in stylesheet_urls {
        let full = format!("{}{}", url.host_str().unwrap_or(""), url.path()).to_ascii_lowercase();

        let rules: &[(&str, &str, &str)] = &[
            ("bootstrap",          "Bootstrap",      "CSS Framework"),
            ("tailwindcss",        "Tailwind CSS",   "CSS Framework"),
            ("tailwind.",          "Tailwind CSS",   "CSS Framework"),
            ("bulma",              "Bulma",          "CSS Framework"),
            ("foundation",         "Foundation",     "CSS Framework"),
            ("materialize",        "Materialize CSS","CSS Framework"),
            ("font-awesome",       "Font Awesome",   "UI Library"),
            ("fontawesome",        "Font Awesome",   "UI Library"),
            ("fonts.googleapis",   "Google Fonts",   "Font Service"),
            ("animate.css",        "Animate.css",    "CSS Library"),
            ("normalize",          "Normalize.css",  "CSS Library"),
            ("reset.css",          "CSS Reset",      "CSS Library"),
            ("jquery-ui",          "jQuery UI",      "UI Library"),
        ];

        for (needle, name, category) in rules {
            if full.contains(needle) {
                let version = extract_version_from_url(&full);
                add(out, TechDetection::medium(name, category, version));
                break;
            }
        }
    }
}

fn check_inline_scripts(inline_scripts: &[String], out: &mut Vec<TechDetection>) {
    let js: String = inline_scripts.join("\n");

    let rules: &[(&str, &str, &str)] = &[
        ("__NEXT_DATA__",      "Next.js",        "Meta Framework"),
        ("__NUXT__",           "Nuxt",           "Meta Framework"),
        ("__SVELTEKIT_APP_VERSION__", "SvelteKit", "Meta Framework"),
        ("window.Shopify",     "Shopify",        "E-Commerce"),
        ("Shopify.theme",      "Shopify",        "E-Commerce"),
        ("window.wc_cart_params", "WooCommerce", "E-Commerce"),
        ("Drupal.settings",    "Drupal",         "CMS"),
        ("wp.i18n",            "WordPress",      "CMS"),
        ("React.createElement","React",          "JavaScript Framework"),
        ("ReactDOM.render",    "React",          "JavaScript Framework"),
        ("ReactDOM.createRoot","React",          "JavaScript Framework"),
        ("new Vue(",           "Vue",            "JavaScript Framework"),
        ("createApp(",         "Vue",            "JavaScript Framework"),
        ("window.angular",     "AngularJS",      "JavaScript Framework"),
        ("stripe.js",          "Stripe",         "Payment"),
        ("gtag(",              "Google Analytics","Analytics"),
        ("ga('send'",          "Google Analytics","Analytics"),
        ("fbq(",               "Meta Pixel",     "Analytics"),
        ("_paq.push",          "Matomo",         "Analytics"),
        ("window.hj",          "Hotjar",         "Analytics"),
    ];

    for (needle, name, category) in rules {
        if js.contains(needle) {
            add(out, TechDetection::medium(name, category, None));
        }
    }
}

fn check_cms_paths(
    dom: &DomSignals,
    script_urls: &[Url],
    stylesheet_urls: &[Url],
    out: &mut Vec<TechDetection>,
) {
    let all_paths: Vec<&str> = dom.paths.iter().map(|s| s.as_str())
        .chain(script_urls.iter().map(|u| u.as_str()))
        .chain(stylesheet_urls.iter().map(|u| u.as_str()))
        .collect();

    let any_path_contains = |needle: &str| all_paths.iter().any(|p| p.to_ascii_lowercase().contains(needle));

    // WordPress.
    if any_path_contains("/wp-content/") || any_path_contains("/wp-includes/") || any_path_contains("wp-json") {
        add(out, TechDetection::high("WordPress", "CMS", None));
    }
    // Drupal.
    if any_path_contains("/sites/default/files/") || any_path_contains("/core/misc/drupal") {
        add(out, TechDetection::high("Drupal", "CMS", None));
    }
    // Ghost.
    if any_path_contains("/ghost/") && any_path_contains("content/") {
        add(out, TechDetection::high("Ghost", "CMS", None));
    }
    // Shopify.
    if any_path_contains("cdn.shopify.com") || any_path_contains(".myshopify.com") {
        add(out, TechDetection::high("Shopify", "E-Commerce", None));
    }
    // WooCommerce.
    if any_path_contains("woocommerce") || any_path_contains("wc-cart") {
        add(out, TechDetection::high("WooCommerce", "E-Commerce", None));
    }
    // Squarespace.
    if any_path_contains("squarespace.com") || any_path_contains("sqspcdn") {
        add(out, TechDetection::high("Squarespace", "Website Builder", None));
    }
    // Wix.
    if any_path_contains("wix.com") || any_path_contains("wixstatic.com") {
        add(out, TechDetection::high("Wix", "Website Builder", None));
    }
    // Webflow.
    if any_path_contains("webflow.com") || any_path_contains("uploads-ssl.webflow") {
        add(out, TechDetection::high("Webflow", "Website Builder", None));
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn add(out: &mut Vec<TechDetection>, tech: TechDetection) {
    if !out.iter().any(|t| t.name == tech.name) {
        out.push(tech);
    }
}

fn extract_version(s: &str) -> Option<String> {
    // Match patterns like "WordPress 6.4.2", "Ghost 5.1", "Joomla! 4.3"
    let re = regex::Regex::new(r"(\d+\.\d+(?:\.\d+)?)").ok()?;
    re.find(s).map(|m| m.as_str().to_string())
}

fn extract_version_from_url(url: &str) -> Option<String> {
    // Match CDN version patterns: @4.0.0, /3.6.1/, -2.1.1.min.js
    let re = regex::Regex::new(r"[@/v](\d+\.\d+(?:\.\d+)?)(?:[/.\-]|$)").ok()?;
    re.find(url).and_then(|m| {
        let s = m.as_str().trim_start_matches(|c| c == '@' || c == '/' || c == 'v');
        let v = s.trim_end_matches(|c: char| !c.is_numeric());
        if v.is_empty() { None } else { Some(v.to_string()) }
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use html5ever::{driver::ParseOpts, parse_document, tendril::TendrilSink};
    use markup5ever_rcdom::RcDom;
    use url::Url;

    /// Parse HTML and run tech detection on the raw (pre-sanitisation) DOM.
    fn detect_from_html(html: &str) -> Vec<super::TechDetection> {
        let base = Url::parse("https://test.example").unwrap();
        let dom = parse_document(RcDom::default(), ParseOpts::default())
            .from_utf8()
            .read_from(&mut Cursor::new(html.as_bytes()))
            .unwrap();

        // Collect script/style URLs from the DOM for the test (simplified).
        let mut script_urls: Vec<url::Url> = Vec::new();
        let mut inline_scripts: Vec<String> = Vec::new();
        let mut stylesheet_urls: Vec<url::Url> = Vec::new();
        collect_resources_for_test(&dom.document, &base, &mut script_urls, &mut inline_scripts, &mut stylesheet_urls);

        super::detect(&dom.document, &script_urls, &inline_scripts, &stylesheet_urls)
    }

    fn collect_resources_for_test(
        handle: &markup5ever_rcdom::Handle,
        base: &url::Url,
        script_urls: &mut Vec<url::Url>,
        inline_scripts: &mut Vec<String>,
        stylesheet_urls: &mut Vec<url::Url>,
    ) {
        use markup5ever_rcdom::NodeData;
        if let NodeData::Element { name, attrs, .. } = &handle.data {
            let tag = name.local.as_ref().to_ascii_lowercase();
            let attrs_ref = attrs.borrow();
            match tag.as_str() {
                "script" => {
                    if let Some(src) = attrs_ref.iter().find(|a| a.name.local.as_ref().eq_ignore_ascii_case("src")) {
                        if let Ok(url) = base.join(src.value.as_ref()) { script_urls.push(url); }
                    } else {
                        let text: String = {
                            let mut buf = String::new();
                            for child in handle.children.borrow().iter() {
                                if let NodeData::Text { contents } = &child.data { buf.push_str(contents.borrow().as_ref()); }
                            }
                            buf
                        };
                        if !text.trim().is_empty() { inline_scripts.push(text); }
                    }
                }
                "link" => {
                    let rel = attrs_ref.iter().find(|a| a.name.local.as_ref().eq_ignore_ascii_case("rel")).map(|a| a.value.as_ref().to_ascii_lowercase()).unwrap_or_default();
                    if rel == "stylesheet" {
                        if let Some(href) = attrs_ref.iter().find(|a| a.name.local.as_ref().eq_ignore_ascii_case("href")) {
                            if let Ok(url) = base.join(href.value.as_ref()) { stylesheet_urls.push(url); }
                        }
                    }
                }
                _ => {}
            }
        }
        for child in handle.children.borrow().iter() {
            collect_resources_for_test(child, base, script_urls, inline_scripts, stylesheet_urls);
        }
    }

    #[test]
    fn detects_wordpress_from_path() {
        let html = r#"<html><head><link rel="stylesheet" href="/wp-content/themes/test/style.css"></head></html>"#;
        let tech = detect_from_html(html);
        assert!(tech.iter().any(|t| t.name == "WordPress"), "expected WordPress, got: {:?}", tech);
    }

    #[test]
    fn detects_angular_ng_version() {
        let html = r#"<html><body><app-root ng-version="17.3.0"></app-root></body></html>"#;
        let tech = detect_from_html(html);
        let angular = tech.iter().find(|t| t.name == "Angular");
        assert!(angular.is_some(), "expected Angular, got: {:?}", tech);
        assert_eq!(angular.unwrap().version.as_deref(), Some("17.3.0"));
    }

    #[test]
    fn detects_nextjs_from_inline_script() {
        let html = r#"<html><body><script>window.__NEXT_DATA__ = {"props":{}}</script></body></html>"#;
        let tech = detect_from_html(html);
        assert!(tech.iter().any(|t| t.name == "Next.js"), "expected Next.js, got: {:?}", tech);
    }

    #[test]
    fn detects_tailwind_from_responsive_classes() {
        let html = r#"<html><body><div class="flex sm:flex-col md:w-1/2 hover:bg-red-500 lg:p-4 dark:text-white"></div></body></html>"#;
        let tech = detect_from_html(html);
        assert!(tech.iter().any(|t| t.name == "Tailwind CSS"), "expected Tailwind CSS, got: {:?}", tech);
    }

    #[test]
    fn detects_vue_scoped_attribute() {
        let html = r#"<html><body><div data-v-7ba5bd90 class="container"></div></body></html>"#;
        let tech = detect_from_html(html);
        assert!(tech.iter().any(|t| t.name == "Vue"), "expected Vue, got: {:?}", tech);
    }

    #[test]
    fn detects_htmx_from_attribute() {
        let html = r#"<html><body><button hx-post="/click" hx-swap="outerHTML">Click</button></body></html>"#;
        let tech = detect_from_html(html);
        assert!(tech.iter().any(|t| t.name == "htmx"), "expected htmx, got: {:?}", tech);
    }
}
