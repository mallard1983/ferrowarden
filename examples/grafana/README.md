# Grafana dashboard and Prometheus setup for Ferrowarden metrics

A dashboard for the [Prometheus metrics](../../docs/metrics.md), a Prometheus scrape configuration, and a Compose file that runs both with the dashboard already loaded.

```
examples/
  grafana/
    ferrowarden-dashboard.json                 the dashboard (import this)
    provisioning/datasources/prometheus.yml    Grafana datasource for the Compose example
    provisioning/dashboards/ferrowarden.yml    loads the dashboard from a folder
  prometheus/
    prometheus.yml                             scrape job with a bearer token read from a file
    docker-compose.yml                         Prometheus + Grafana, pinned images
```

## What the dashboard shows

| Row | Panels |
|---|---|
| Traffic | Forward requests by outcome; blocked and failed requests by reason; forward latency (p50, p95); upstream response size (p50, p95); requests by agent key |
| Security | Authentication failures by kind (agent, admin, ui, metrics); rate-limited requests by limiter; agent keys without a policy (red above 0) |
| Vault | Locked or unlocked; credentials in the cache; time since the last sync; items the native backend left out |
| Notifications and events | Notifications by sender and result; dropped events (event sinks, and metrics) |

It has two variables: **Data source** (any Prometheus data source; no UID is built in, so the dashboard imports anywhere) and **Instance** (one or more Ferrowarden instances, or all). The per-credential counter of [`metrics.credential_labels`](../../docs/metrics.md#credential-names-as-labels-opt-in) has no panel: it is off by default and the names it uses reveal what the vault holds.

## Run it

1. Turn on the metrics listener in Ferrowarden and give it a token ([docs/metrics.md](../../docs/metrics.md#turn-it-on)). The token is a file, for example `secrets/metrics_token`.
2. Put Ferrowarden and Prometheus on a network only they share, so the metrics port is never published:

   ```sh
   docker network create ferrowarden-metrics
   # add `ferrowarden-metrics` to the ferrowarden service's networks in docker-compose.yml
   ```

3. Start Prometheus and Grafana:

   ```sh
   cd examples/prometheus
   docker compose up -d
   ```

   Prometheus is on <http://localhost:9090> (Status, then Targets: the `ferrowarden` job should be `UP`) and Grafana on <http://localhost:3030> (user `admin`, password `admin`: change it). The dashboard is under Dashboards, **Ferrowarden**.

`prometheus.yml` scrapes `ferrowarden:9095` and sends the token from `credentials_file`. With `tls_enabled = true` in Ferrowarden, use `scheme: https` and `tls_config.ca_file` as the comments in the file say.

## Import it into an existing Grafana

In Grafana: Dashboards, New, Import, upload `ferrowarden-dashboard.json`, and pick your Prometheus data source. Or through the API (a service account token with the editor role):

```sh
curl -X POST http://grafana.example.lan:3000/api/dashboards/db \
  -H "Authorization: Bearer $GRAFANA_TOKEN" -H "Content-Type: application/json" \
  -d "{\"dashboard\": $(cat ferrowarden-dashboard.json), \"overwrite\": true}"
```

The dashboard's queries use the `instance` label that Prometheus adds, so any job name works.

## How it was tested

The dashboard and the Compose example were run against the Ferrowarden test stack (both instances, `bw serve` and native) while the integration suites ran:

- Prometheus 3.15.1 scraped both metrics listeners with the token file (`up` for both).
- Every panel query of the dashboard, with `$instance` and `$__rate_interval` filled in, returned data from Prometheus's HTTP API (`/api/v1/query`).
- Grafana 13.2.7 started with the provisioning files in this folder, loaded the dashboard without errors, and the same queries answered through Grafana's own data source API (`/api/ds/query`).
- The dashboard was also imported through the HTTP API (`POST /api/dashboards/db`) into a Grafana with a provisioned data source.

The dashboard JSON was not exported from a Grafana session, so it holds no data source UID or panel ID from anyone's installation.
