# Sysdig Secure Exporter

## Intro

This Prometheus Exporter exports Sysdig Secure REST API data to Prometheus metrics.

You can find more details about the Sysdig Secure REST API in the Sysdig Secure REST API [Swagger](https://secure.sysdig.com/swagger.htm) (for the US1 region) or [documentation](https://docs.sysdig.com/en/docs/developer-tools/sysdig-rest-api-conventions/).

To run it:

```sh
go build
./sysdig_secure_exporter [flags]
```

## Exported metrics

Following is a complete list of exported metrics and their labels following the [Prometheus metric and label naming](https://prometheus.io/docs/practices/naming/) convention:

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
| sysdig_secure_top_cluster_events_total         | What are the top column values and counts of events by kubernetes cluster ?           | cluster, label |
| sysdig_secure_top_namespace_events_total       | What are the top column values and counts of events by kubernetes namespace ?         | namespace, label |
| sysdig_secure_top_node_events_total            | What are the top column values and counts of events by kubernetes node ?              | node, label |
| sysdig_secure_top_mitre_events_total           | What are the top column values and counts of events by mitre ?                        | mitre, label |
| sysdig_secure_top_rule_events_total            | What are the top column values and counts of events by rule name ?                    | rule, label |
| sysdig_secure_top_workload_events_total        | What are the top column values and counts of events by workload ?                     | workload, label |

## Flags

Usage:

```sh
./sysdig_secure_exporter -help
```

As you may see from the usage, following is a list of available command line flags:

| Flag               | Description                        | Default    |
| ------------------ | ---------------------------------- | ---------- |
| api.stat-rows      | Number of rows in top stat APIs    | 5          |
| api.time-window    | Time period for event count APIs   | "24h"      |
| config.env-file    | Environment file path              |            |
| config.log-level   | Logging level | severity           | "info"     |
| web.listen-address | Address to listen on for metrics   | ":9100"    |
| web.metrics-path   | Path under which to expose metrics | "/metrics" |

For more information about the API subset of command line flags (like 'time-window' or 'stat-rows'), refer to the Secure Events section in the Sysdig Secure REST API swagger: <https://secure.sysdig.com/swagger.html#tag/Secure-Events>

## Environment variables

The Sysdig Secure REST API URL and authorization token may be provided either via environment variables or using an environment file (.env with the [GoDotEnv](https://github.com/joho/godotenv) library) which path can be provided with the `-config.env-file` command line flag.

| Environment variable              | Description                                         | Default                     |
| --------------------------------- | --------------------------------------------------- | --------------------------- |
| SYSDIG_SECURE_API_ENDPOINT        | API URL corresponding to the Saas region            | "https://secure.sysdig.com/" |
| SYSDIG_SECURE_API_KEY             | API token to be passed via the Authorization header |                             |

For more information about the API SaaS regions and IP ranges, refer to the Sysdig Secure documentation: <https://docs.sysdig.com/en/docs/administration/saas-regions-and-ip-ranges/#saas-regions-and-ip-ranges>

## Using Docker

You can use the [Dockerfile](./Dockerfile) to build the Prometheus Exporter and run it like this (after updating the .env file with the API endpoint and key):

```sh
docker build -t sysdig_secure_exporter .
docker run -t --rm \
    --name sysdig-secure-exporter -p 9100:9100 \
    -v $(pwd)/sysdig_secure_exporter.env:/tmp/sysdig-secure-exporter.env \
    sysdig_secure_exporter -config.env-file /tmp/sysdig-secure-exporter.env
```

Then, you can run this curl to see the Sysdig Secure Prometheus metrics:

```sh
curl localhost:9100/metrics
```

## Important information

This Prometheus exporter is inspired from the [Mirth Channel Exporter](https://github.com/teamzerolabs/mirth_channel_exporter) by TeamZeroLabs. Read their Medium article for more info: [15 Steps to Write an Application Prometheus Exporter in GO](https://medium.com/teamzerolabs/15-steps-to-write-an-application-prometheus-exporter-in-go-9746b4520e26)

## TODO

- Fix Docker build issues:

```sh
amemni@LT-C3D10Z2:~/Desktop/Repos/others/amemni/sysdig_secure_exporter$ docker run --rm     --name sysdig-secure-exporter -p 9100:9100     -v $(pwd)/sysdig_secure_exporter.env:/tmp/sysdig-secure-exporter.env     sysdig_secure_exporter -- -config.env-file /tmp/sysdig-secure-exporter.env
time="2022-12-24T21:30:07Z" level=info msg="Using Sysdig Secure API endpoint: https://secure.sysdig.com/"
time="2022-12-24T21:30:07Z" level=info msg="Using API time window (diff. btw 'from' and 'to'): 24 hours"
time="2022-12-24T21:30:12Z" level=fatal msg="invalid character 'o' in literal null (expecting 'u')"
amemni@LT-C3D10Z2:~/Desktop/Repos/others/amemni/sysdig_secure_exporter$
```

- Testing with curl:

```sh
curl -s -H "Authorization: Bearer $SYSDIG_SECURE_API_KEY" -H "Accept: application/json" -X GET 'https://us2.app.sysdig.com/api/v1/secureEvents/topStats?from=1671883040981752398&to=1671969440981752398&rows=5' | jq
```
