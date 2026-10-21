# Expose Platform — self-hosted permanent subdomain gateway

Create stable HTTPS subdomains for **publicly reachable HTTP services hosted on completely different VPS servers**. Includes a dark admin dashboard, password authentication, MongoDB, Docker Compose, Caddy wildcard TLS and an HTTP/WebSocket reverse proxy.

## Architecture

Browser → Cloudflare proxied wildcard `*.example.com` → gateway VPS (Caddy HTTPS) → Node proxy → `PUBLIC_VPS_IP:PORT`.

One central gateway is necessary. Every target VPS may be from a different provider. **No tunnel agent needed only when the target HTTP port is reachable by the gateway.** Private-only/localhost ports require an agent or private overlay network (not included).

## Requirements

- A Linux gateway VPS with public IPv4 and Docker Compose v2, with inbound 80 and 443 allowed.
- Your domain using **Cloudflare full DNS setup**.
- Public HTTP upstreams accessible from gateway; don't expose admin/database ports.
- Cloudflare API token with **Zone → DNS → Edit** restricted to this zone (for DNS-01 certificate verification).
- MongoDB runs in its private Docker network and is not exposed to the internet.

## Install

```bash
cp .env.example .env
# edit .env: BASE_DOMAIN, ADMIN_PASSWORD, SESSION_SECRET, CLOUDFLARE_API_TOKEN
# generate secrets, e.g. `openssl rand -hex 32`
docker compose up -d --build
```

**One-time Cloudflare settings** in the zone:

1. Add wildcard `A` DNS record `*` → **public IPv4 of your gateway VPS**, proxy **ON (orange cloud)**.
2. Set SSL/TLS encryption mode to **Full (strict)**; the gateway Caddy certificate is acquired using Cloudflare DNS challenge.
3. Ensure Cloudflare's Universal SSL certificate is active for first-level subdomains. Caddy also provisions a wildcard origin certificate via DNS challenge (may take time for DNS propagation).
4. Keep your chosen `panel` subdomain reserved for admin UI. Do not add conflicting explicit DNS records unless pointing at the same gateway.
5. Access `https://panel.example.com` (replace `example.com` with `BASE_DOMAIN`). Log in using `ADMIN_PASSWORD`.

**Important:** The dashboard creates reserved URLs immediately in MongoDB; public reachability depends on DNS, certificate issuance, Cloudflare, the gateway and upstream actually being online. This app does not automatically create Cloudflare records: *the wildcard record is the one-time setup*. Each new endpoint requires **no further DNS/API changes**.

## Usage

On the dashboard create a mapping for e.g. `45.67.89.10`, port `3000`. You'll receive something like `https://e4c7ad0f91a82.example.com` and it remains bound to that service across restarts because MongoDB stores it. Disable/delete via dashboard. **Deleted slugs are tombstoned (never intentionally reused).** Keep MongoDB volumes/backups to preserve this guarantee.

For safety only global public IPv4 literals are accepted (no private IP, DNS names, localhost or common sensitive service ports). Only `http://IP:PORT` upstreams are supported. WebSocket upgrade is supported. HTTP URL paths/query strings are preserved. No arbitrary TCP/UDP protocols.

## API

Admin-only endpoints use an HTTP-only, SameSite=Strict session cookie:

- `POST /api/login` with `{ "password": "..." }`
- `GET /api/session`
- `GET /api/endpoints`
- `POST /api/endpoints` with `{ "host": "45.67.89.10", "port": 3000, "name": "My API" }`
- `PATCH /api/endpoints/:id` with `{ "active": false }`
- `DELETE /api/endpoints/:id` (soft delete)
- `POST /api/logout`

## Running locally (without Cloudflare)

Run MongoDB locally, set `BASE_DOMAIN=example.com`, `COOKIE_SECURE=false`, `MONGO_URI=mongodb://127.0.0.1:27017/expose`, choose strong passwords in `.env`, then:

```bash
npm install
npm test
npm run dev
```

Visit `http://localhost:8080` for dashboard. **Generated example.com URLs won't resolve locally** unless you control DNS and deploy gateway.

## Operations and security

- Gateway is public infrastructure: harden the OS and Docker, restrict SSH, enable backups, set monitoring, keep images updated.
- Do not allow untrusted accounts to register destinations. Admin-only, public-IP validation and denied sensitive ports reduce SSRF exposure but do not make unrestricted third-party exposure safe. Add egress firewall rules, rate limiting and abuse protection before opening public registrations.
- Cloudflare proxy supports HTTP/WebSocket but enforces network restrictions and allowed proxy ports on the Cloudflare → origin hop (normally 443 here).
- Target VPS upstream traffic from gateway is **plain HTTP**, possibly over the public internet. For sensitive user data use a trusted private overlay network with TLS or extend upstream HTTPS with verification.
- If a target service is publicly reachable directly, the public IP:PORT can bypass your Cloudflare gateway. Restrict the target firewall to the gateway's IP if possible.
- Disable direct public access to gateway app port 8080 (Compose doesn't publish it).
- Cookie login sessions expire after 7 days. Rotating `SESSION_SECRET` invalidates sessions.
- Restart/redeploy: `docker compose up -d --build`. Update and backup volume `mongo_data` and `caddy_data`.
- Do not run this as an unrestricted public SaaS as-is: missing tenant isolation, quotas, billing, advanced auth, extensive abuse controls, observability and HA.
