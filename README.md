# Sysdig Secure Exporter

## Intro

This Prometheus Exporter exports Sysdig Secure API metrics to Prometheus.

It retrieves metrics from the Sysdig Secure REST API. You can find more details in the Sysdig Secure REST API [Swagger](https://secure.sysdig.com/swagger.htm) (for the US1 region) or [documentation](https://docs.sysdig.com/en/docs/developer-tools/sysdig-rest-api-conventions/).

To run it:

```sh
go build
./sysdig_secure_exporter [flags]
```

## TODO

What remains:

- README
- Docker
- Env variables
- QA and unit tests (test order change ..etc)

## Exported metrics

| Metric                                         | Meaning                                                                               | Labels       |
| ---------------------------------------------- | ------------------------------------------------------------------------------------- | ------------ |
| up                                             | Was the last Sysdig Secure API query successful ?                                     |              |
| sysdig_secure_scanning_events_total            | How many scanning events have been generated in the selected time window ?            | severity     |
| sysdig_secure_policy_events_total              | How many policy events have been generated in the selected time window ?              | severity     |
| sysdig_secure_profiling_detection_events_total | How many profiling detection events have been generated in the selected time window ? | severity     |
| sysdig_secure_host_scanning_events_total       | How many host scanning events have been generated in the selected time window ?       | severity     |
| sysdig_secure_benchmark_events_total           | How many benchmark events have been generated in the selected time window ?           | severity     |
| sysdig_secure_compliance_events_total          | How many compliance events have been generated in the selected time window ?          | severity     |
| sysdig_secure_cloudsec_events_total            | How many cloudsec events have been generated in the selected time window ?            | severity     |
| sysdig_secure_top_image_events_total           | What are the top column values and counts of events by container image ?              | image, label |
| sysdig_secure_top_cluster_events_total         | What are the top column values and counts of events by kubernetes cluster ?           | image, label |
| sysdig_secure_top_namespace_events_total       | What are the top column values and counts of events by kubernetes namespace ?         | image, label |
| sysdig_secure_top_node_events_total            | What are the top column values and counts of events by kubernetes node ?              | image, label |
| sysdig_secure_top_mitre_events_total           | What are the top column values and counts of events by mitre ?                        | image, label |
| sysdig_secure_top_rule_events_total            | What are the top column values and counts of events by rule name ?                    | image, label |
| sysdig_secure_top_workload_events_total        | What are the top column values and counts of events by workload ?                     | image, label |

## Flags

Usage:

```sh
./sysdig_secure_exporter -help
```

| Flag               | Description                        | Default    |
| ------------------ | ---------------------------------- | ---------- |
| api.stat-rows      | Number of rows in top stat APIs    | 5          |
| api.time-window    | Time period for event count APIs   | "24h"      |
| config.env-file    | environment file path              |            |
| config.log-level   | logging level | severity           | "info"     |
| web.listen-address | address to listen on for metrics   | ":9100"    |
| web.metrics-path   | path under which to expose metrics | "/metrics" |

For more information about the API flags subset (like 'time-window' or 'stat-rows'), refer to the Secure Events section in the Sysdig Secure REST API swagger: <https://us2.app.sysdig.com/secure/swagger.html#tag/Secure-Events>

## Environment variables

It is also possible to use an environment file (.env) and provider the path with the `-config.env-file` flag.

| Environment variable              | Description                        | Default    |
| --------------------------------- | ---------------------------------- | ---------- |
| SYSDIG_SECURE_API_STAT_ROWS       | Number of rows in top stat APIs    | 5          |
| SYSDIG_SECURE_API_TIME_WINDOW     | Time period for event count APIs   | "24h"      |
| SYSDIG_SECURE_CONFIG_LOG_LEVEL    | logging level | severity           | "info"     |
| SYSDIG_SECURE_WEB_LISTEN_ADDRESS  | address to listen on for metrics   | ":9100"    |
| SYSDIG_SECURE_WEB_METRICS_PATH    | path under which to expose metrics | "/metrics" |

## Using Docker

// TODO

## Important information

This Prometheus exporter is inspired from the [Mirth Channel Exporter](https://github.com/teamzerolabs/mirth_channel_exporter) by TeamZeroLabs. Read their Medium article for more info: <https://medium.com/teamzerolabs/15-steps-to-write-an-application-prometheus-exporter-in-go-9746b4520e26>
