# 10 — Expose Geonosis as a SAML IdP to a SaaS app

## What you'll have at the end

A downstream SaaS app (Confluence, Tableau, Workday, your own
Spring Boot, …) trusts Geonosis as its SAML 2.0 Identity Provider
and lets your realm's users sign in via SP-initiated SSO.

This recipe is for the **IdP role** ([`20-saml-idp.md`](../20-saml-idp.md));
broker SP role (consuming external SAML IdPs) is recipe-worthy in
its own right but separate.

## Prerequisites

- A running realm `acme` with at least one Active signing key (an
  RS256 key works fine; ES256 also accepted).
- The downstream SaaS app's SAML SP entity-id and ACS URL (you
  get these from its SAML setup screen).
- `frontend_url` correctly set on the realm
  ([`07-deploy-behind-ingress.md`](./07-deploy-behind-ingress.md)).

## Steps

1. **Register the SP as a Client.**

   ```sh
   geoctl clients create \
     --realm acme \
     --client-id confluence-prod \
     --kind SamlServiceProvider \
     --saml-config '{
       "entity_id":"https://confluence.acme.example",
       "acs_urls":["https://confluence.acme.example/plugins/servlet/samlconsumer"],
       "slo_url":"https://confluence.acme.example/plugins/servlet/samlslo",
       "binding":"HttpPost",
       "name_id_format":"emailAddress",
       "want_authnrequest_signed":true,
       "want_assertions_encrypted":false,
       "signing_key":"<KID of your active sig key>",
       "session_index_strategy":"UseSessionId"
     }' \
     --attribute-mappers '[
       {"mapper_urn":"builtin:mapper:saml-attribute","config":{
         "attribute":"email","saml_name":"email",
         "saml_format":"urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
       }},
       {"mapper_urn":"builtin:mapper:saml-role","config":{
         "saml_name":"Role",
         "saml_format":"urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
       }}
     ]'
   ```

   The `mapper_urn`s are the same `geonosis:mapper@0.1.0` interface
   the OIDC token-claim mappers use — the SAML builder serializes
   their output as `<Attribute>` statements
   ([`20-saml-idp.md`](../20-saml-idp.md) §Attribute mapping).

2. **(If the SP signs its AuthnRequests) upload the SP's signing
   cert.**

   ```sh
   geoctl clients saml-cert-add \
     --realm acme \
     --client confluence-prod \
     --purpose authnrequest-signing \
     --cert-file confluence-sp.crt
   ```

   Without this, AuthnRequest signatures can't be verified and
   `want_authnrequest_signed=true` rejects every login.

3. **Download Geonosis's IdP metadata.**

   ```sh
   curl -fsS https://geonosis.example.com/realms/acme/protocol/saml/descriptor \
     -o geonosis-acme-idp.xml
   ```

   This XML declares:
   - `EntityID` = realm's `frontend_url`
   - All currently Active + PreviousActive signing keys
   - `SingleSignOnService` at `.../protocol/saml/sso`
   - `SingleLogoutService` at `.../protocol/saml/slo`
   - Supported `NameIDFormat`s

4. **Configure the downstream app.**

   Upload `geonosis-acme-idp.xml` (or paste its contents) into
   the SaaS app's SAML configuration. The exact UI varies by app:

   - **Confluence Data Center**: Settings → Authentication →
     SAML2 → Configure → Upload IdP metadata.
   - **Tableau Server**: Settings → User Identity & Access →
     Identity Store → SAML.
   - **Your own app**: depends on your SAML library.

   The SP-side configuration tells the app *where* to send
   AuthnRequests and *how* to trust our assertions.

5. **Test SP-initiated SSO.**

   Visit the downstream app's "Sign in with SSO" button. Browser
   trace:

   ```
   1. App POSTs <AuthnRequest> to .../protocol/saml/sso
   2. Geonosis runs the browser flow — user authenticates
   3. Geonosis POSTs <Response> with <Assertion> back to ACS URL
   4. App accepts, creates local session, redirects to home
   ```

## Verifying

Browser dev tools: the second POST request body decodes (Base64,
maybe-zlib) to a SAML Response with:

```xml
<saml2:Issuer>https://geonosis.example.com/realms/acme</saml2:Issuer>
<saml2:Subject>
  <saml2:NameID Format="...emailAddress">ada@acme.test</saml2:NameID>
</saml2:Subject>
<saml2:AttributeStatement>
  <saml2:Attribute Name="email">ada@acme.test</saml2:Attribute>
  <saml2:Attribute Name="Role">user</saml2:Attribute>
</saml2:AttributeStatement>
```

And:

```sh
geoctl audit list --realm acme --action 'saml.assertion_issued' --limit 5
```

shows recent issuances with the client_id.

## SLO (single logout)

When `ada` clicks "Sign out" in Confluence, Confluence POSTs a
LogoutRequest to `.../protocol/saml/slo`. Geonosis:

1. Closes ada's local browser SSO session.
2. Iterates every SP she was logged into during that session.
3. POSTs a LogoutRequest to each SP's SLO URL (or renders an
   iframe for front-channel logout).
4. Returns a LogoutResponse to Confluence.

## Troubleshooting

- **`InvalidSignature` from the SP** — your realm's signing-key
  cert chain isn't trusted by the SP. Re-download metadata after
  key rotation; some apps cache too aggressively.
- **`AudienceRestriction` mismatch** — set
  `default_audience` on the client to the SP's expected audience.
  Default is the SP's `entity_id`.
- **NameID changes per login** — you're using `transient` instead
  of `persistent`/`emailAddress`. Change `name_id_format`.
- **SLO doesn't log out the SP** — the SP didn't configure an
  SLO URL or didn't trust the LogoutRequest signature. Some apps
  require front-channel logout via iframe, set
  `slo_url` to an empty value to disable back-channel and rely on
  front-channel only.

## See also

- [`20-saml-idp.md`](../20-saml-idp.md) — Assertion construction,
  NameID strategies, SLO mechanics.
- [`05-identity-broker.md`](../05-identity-broker.md) — The SP
  role (consuming external SAML).
