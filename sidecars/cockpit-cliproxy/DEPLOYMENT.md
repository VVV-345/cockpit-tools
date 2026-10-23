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

## Admin sync API

These endpoints are the initial server-side sync contract for the migration.
They do not yet provide the complete account-management API, move the existing
account database, or implement the LiteLLM management adapter. The current
manager remains responsible for supplying snapshots until that adapter is
implemented. Set `COCKPIT_ADMIN_TOKEN` to a dedicated secret to enable admin
requests. Client API keys are not accepted. Keep the endpoint on a private
network and never expose this token to browser clients.

`GET /admin/v1/manifest` returns the current on-disk manifest and an `ETag`.
`PUT /admin/v1/manifest` requires that value in `If-Match`, validates the JSON,
and atomically persists a snapshot.

`GET /admin/v1/auth-files` returns credential file IDs, ETags, and sizes without
returning credential contents. `PUT /admin/v1/auth-files/:name` accepts one
CLIProxyAPI auth JSON object up to 4 MiB. Creating a file requires
`If-None-Match: *`; replacing one requires its current `If-Match` ETag.
`DELETE /admin/v1/auth-files/:name` also requires the current `If-Match` ETag.
Credential files are written atomically with mode `0600`.

Successful writes return `202 Accepted`, a new ETag when applicable, and
`restartRequired: true`. The running gateway continues using its startup
manifest and auth snapshot until restarted. After a batch of writes, call
`POST /admin/v1/restart` with the same admin token to request a graceful process
shutdown. The endpoint returns `202 Accepted`; the process gives active HTTP
requests the existing ten-second shutdown window before exiting. A supervisor
must restart the process for the updated snapshot to take effect. The Compose
service uses `restart: unless-stopped`. Without an external supervisor, the
process exits and must be started manually.

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
require a key from `manifest.json`. The target migration keeps LiteLLM as the
public API and usage-accounting layer while Cockpit takes ownership of account
selection and backend routing. This API does not implement that cutover yet.
