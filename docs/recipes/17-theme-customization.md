# 17 — Customize the login theme

## What you'll have at the end

Realm `master` has a custom login theme with your company logo,
brand colors, and a modified login page — hot-reloadable without
restarting any pod.

## Prerequisites

- A running Geonosis deployment with a theme volume mounted.
- For K8s: the Helm chart mounts `/themes/` from a ConfigMap
  or PersistentVolume by default.
- For Docker quickstart: mount a local directory with
  `-v ./my-theme:/themes/acme-brand`.

## Steps

1. **Create the theme directory structure.**

   ```sh
   mkdir -p my-theme/{login/assets,email}
   ```

   Create `my-theme/theme.toml`:

   ```toml
   [meta]
   name = "acme-brand"
   display_name = "Acme Brand Theme"
   extends = "default"          # inherit everything not overridden

   [login]
   template_dir = "login"
   assets_dir = "login/assets"

   [email]
   template_dir = "email"
   ```

2. **Add brand assets.**

   ```sh
   cp /path/to/logo.svg my-theme/login/assets/logo.svg
   ```

   Create `my-theme/login/assets/theme.css`:

   ```css
   :root {
     --geonosis-primary: #1f6feb;
     --geonosis-primary-hover: #1a5dd4;
     --geonosis-bg: #fafbfc;
     --geonosis-text: #1f2328;
     --geonosis-logo-url: url("/themes/acme-brand/login/assets/logo.svg");
     --geonosis-logo-height: 48px;
   }

   /* Override only what you need — the rest inherits from default */
   .login-card {
     border-radius: 12px;
     box-shadow: 0 2px 8px rgba(0, 0, 0, 0.08);
   }
   ```

   **Security:** Never use `<style>` tags or inline JS in
   templates. The default CSP header blocks inline scripts.
   Use CSS custom properties and external stylesheets only.

3. **Override the login page template (optional).**

   Copy the default template and modify:

   ```sh
   geoctl theme export-template --name default --template login/login.html \
     > my-theme/login/login.html
   ```

   Edit `my-theme/login/login.html` — the template uses
   Maud/Askama-style syntax with auto-escaping:

   ```html
   <!-- Variables are auto-escaped by default -->
   <h1 class="login-title">{{ realm_display_name }}</h1>

   <!-- Add a custom banner -->
   <div class="custom-banner">
     Welcome to {{ realm_display_name }}. Please sign in.
   </div>
   ```

   Templates are **escape-by-default** — `{{ var }}` HTML-escapes,
   `{{{ var }}}` is raw (use only for pre-sanitized HTML like
   `display_name_html`).

4. **Mount and bind the theme.**

   For Docker:

   ```sh
   docker run -v $(pwd)/my-theme:/themes/acme-brand \
     -e GEONOSIS_THEME_DIRS=/themes \
     ghcr.io/hosnian-prime/geonosis-server:latest
   ```

   For K8s, add to Helm values:

   ```yaml
   theme:
     volumes:
       - name: acme-brand
         configMap:
           name: acme-brand-theme
     mountPath: /themes/acme-brand
   ```

5. **Bind the theme to the realm.**

   ```sh
   geoctl realm patch --realm master \
     --theme-binding '{"login": "acme-brand", "email": "acme-brand"}'
   ```

## Verifying

Open the login page:

```sh
open "https://geonosis.example.com/realms/master/protocol/openid-connect/auth?\
client_id=master-web&response_type=code&redirect_uri=http://127.0.0.1:8888/callback&scope=openid"
```

You should see your logo, brand colors, and any template changes.

## Hot reload

Edit `my-theme/login/assets/theme.css`, save. The file watcher
(`notify` crate with `inotify`/`kqueue`) detects the change and
reloads the theme engine within ~100 ms. No pod restart, no
request drop.

```sh
# Watch the reload event:
geoctl audit list --realm master --action 'theme.reloaded' --limit 1
```

## Accessibility checklist

The default theme is **WCAG 2.1 AA** compliant. When customizing:

- Maintain contrast ratio ≥ 4.5:1 for text, ≥ 3:1 for large text.
- Keep focus indicators visible (`outline` or equivalent).
- Use CSS logical properties (`margin-inline-start` not
  `margin-left`) for RTL support.
- Test with a screen reader — the default theme uses ARIA
  landmarks.

## Troubleshooting

- **Theme not appearing** — check the mount path matches
  `GEONOSIS_THEME_DIRS` and the `theme.toml` `name` matches
  the `theme_binding` value.
- **CSS not loading** — CSP may block external URLs. Assets
  must be served from the theme's own `assets_dir`.
- **Template syntax error** — the server logs a warning with the
  file and line number. Fix the template; hot reload picks it up.
- **RTL layout broken** — ensure `dir="auto"` on the `<html>`
  tag and use CSS logical properties throughout.

## See also

- [`08-admin-ui.md`](../08-admin-ui.md) — Theme engine, slot
  overrides, Leptos component model.
- [`02-data-model.md`](../02-data-model.md) — `ThemeBinding`,
  `SecurityHeaders` (CSP).
