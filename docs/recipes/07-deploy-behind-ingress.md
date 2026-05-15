# 07 — Deploy Geonosis behind nginx / Caddy / Traefik

## What you'll have at the end

Geonosis running in your Kubernetes cluster, fronted by a TLS-
terminating ingress controller of your choice, reachable at
`https://geonosis.example.com`, with `frontend_url` set so issued
tokens have the right `issuer` value.

## Prerequisites

- A Kubernetes cluster with one of: ingress-nginx, Caddy, or
  Traefik installed.
- `cert-manager` installed with a working `ClusterIssuer` (Let's
  Encrypt, internal CA, ...).
- Postgres + Redis already running (managed or in-cluster).
- `helm` available locally.

## Steps

1. **Install the Helm chart, ingress off.**

   We'll let the chart provision the Deployment + Service + PDB,
   but we manage the Ingress ourselves so we can use any
   controller.

   ```sh
   helm repo add geonosis https://charts.geonosis.dev
   helm install geonosis geonosis/geonosis \
     --namespace iam --create-namespace \
     --set database.urlSecretRef=postgres-secret \
     --set cache.redis.urlSecretRef=redis-secret \
     --set crypto.masterKeySecretRef=geonosis-master-key \
     --set ingress.enabled=false \
     --set server.frontendUrl=https://geonosis.example.com
   ```

   `frontendUrl` is critical — it becomes the `iss` claim in
   tokens and the base for every redirect Geonosis emits.

2. **Ingress: pick your controller.**

   ### nginx-ingress

   ```yaml
   apiVersion: networking.k8s.io/v1
   kind: Ingress
   metadata:
     name: geonosis
     namespace: iam
     annotations:
       cert-manager.io/cluster-issuer: letsencrypt-prod
       nginx.ingress.kubernetes.io/proxy-body-size: "1m"
       nginx.ingress.kubernetes.io/proxy-buffer-size: "16k"
       nginx.ingress.kubernetes.io/server-snippet: |
         add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
   spec:
     ingressClassName: nginx
     tls:
       - hosts: [geonosis.example.com]
         secretName: geonosis-tls
     rules:
       - host: geonosis.example.com
         http:
           paths:
             - path: /
               pathType: Prefix
               backend:
                 service:
                   name: geonosis
                   port: { number: 8080 }
   ```

   ### Caddy

   ```yaml
   apiVersion: networking.k8s.io/v1
   kind: Ingress
   metadata:
     name: geonosis
     namespace: iam
     annotations:
       cert-manager.io/cluster-issuer: letsencrypt-prod
   spec:
     ingressClassName: caddy
     # Caddy handles TLS via cert-manager-provisioned Secret.
     tls:
       - hosts: [geonosis.example.com]
         secretName: geonosis-tls
     rules:
       - host: geonosis.example.com
         http:
           paths:
             - { path: /, pathType: Prefix, backend: { service: { name: geonosis, port: { number: 8080 } } } }
   ```

   ### Traefik (CRD form)

   ```yaml
   apiVersion: traefik.io/v1alpha1
   kind: IngressRoute
   metadata: { name: geonosis, namespace: iam }
   spec:
     entryPoints: [websecure]
     routes:
       - match: Host(`geonosis.example.com`)
         kind: Rule
         services: [{ name: geonosis, port: 8080 }]
     tls:
       secretName: geonosis-tls
   ```

3. **Make sure the realm's frontend URL matches.**

   Per realm, set:

   ```sh
   geoctl realm patch --realm master --frontend-url https://geonosis.example.com
   geoctl realm patch --realm master   --frontend-url https://geonosis.example.com
   ```

   (Or set them via the admin UI under Realm settings → General.)

4. **Trust headers from the ingress.**

   The chart's default `server.trustedProxies` accepts only
   K8s-internal CIDRs. If your ingress strips `X-Forwarded-*`
   and re-injects them, this is automatic. Don't trust
   `X-Forwarded-*` from outside the cluster.

## Verifying

```sh
curl -fsSL https://geonosis.example.com/realms/master/.well-known/openid-configuration | jq .issuer
```

Expected: `"https://geonosis.example.com/realms/master"`.

Cert is valid:

```sh
echo | openssl s_client -connect geonosis.example.com:443 -servername geonosis.example.com 2>/dev/null | openssl x509 -noout -dates
```

Within a known good range.

## Troubleshooting

- **`error=invalid_redirect_uri`** when an app tries to log in —
  the app's registered `redirect_uri` is HTTP and your realm
  enforces `ssl_required=ExternalRequests`. Switch the app to
  HTTPS or change the realm's SSL requirement (not recommended in
  production).
- **`frontend_url` mismatch warnings** in logs — discovery doc's
  `issuer` doesn't match the value tokens were signed with for an
  older session. Bump up `SessionPolicy.sso_session_idle`
  temporarily to bleed off old sessions, or revoke all.
- **502 from the ingress** — pod's readiness probe is failing.
  `kubectl describe pod -n iam` for events; common cause is the
  cache backend (Redis) being unreachable.

## See also

- [`11-deployment-k8s.md`](../11-deployment-k8s.md) — Helm chart
  values reference + ingress notes.
- [`12-security-crypto.md`](../12-security-crypto.md) — TLS,
  HSTS, security headers.
