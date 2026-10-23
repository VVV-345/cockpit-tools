# Cockpit Gateway Service

This container runs the Go gateway without launching the Cockpit desktop app. It
expects `config.yaml`, `manifest.json`, provider auth files, and writable state
files under `/data`.

## Required files

Set `host: 0.0.0.0`, `port: 8317`, and `auth-dir: /data/auth` in `config.yaml`.
The manifest must contain the enabled client API keys and their authorized
account IDs. Do not put real credentials in this repository.

The service persists quota cooldown and reserve state in `/data`. Keep that
directory on durable storage and restrict access because the config, manifest,
and auth files may contain secrets.

## Run locally

Create `data/config.yaml`, `data/manifest.json`, and `data/auth/`, then run:

```sh
mkdir -p data/auth
sudo chown -R 10001:10001 data
docker compose -f compose.service.yml up --build -d
```

The example publishes the gateway only on host loopback at port 8317. When
LiteLLM runs in another container, attach both services to a private Docker
network and use `http://cockpit-backend:8317/v1`; do not expose the gateway
publicly without an authenticated TLS boundary.

`GET /healthz` is an unauthenticated liveness probe. Client API routes still
require a key from `manifest.json`. This image does not yet provide the Cockpit
desktop management UI or an account-management REST API; the manifest remains
the account-pool input until the LiteLLM management adapter is implemented.
