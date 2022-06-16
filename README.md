# sysdig_secure_exporter

A Prometheus exporter for Sysdig Secure

## Installation

TODO

## Usage

TODO

## Brainstorming

### Testing the Sysdig Secure API

Examples:

- Overview:

```bash
curl -s -H "Authorization: Bearer $SYSDIG_API_KEY" -H "Accept: application/json" -X GET https://us2.app.sysdig.com/api/v1/secure/overview | jq
```

- Audit events:

```bash
curl -s -H "Authorization: Bearer $SYSDIG_API_KEY" -H "Accept: application/json" -X GET 'https://us2.app.sysdig.com/api/v1/activityAudit/events?from=1654074448000000000&to=1655284048000000000' | jq
```

- Secure events:

```bash
curl -s -H "Authorization: Bearer $SYSDIG_API_KEY" -H "Accept: application/json" -X GET 'https://us2.app.sysdig.com/api/v1/secureEvents/count?from=1654074448000000000&to=1655284048000000000' | jq
```

You can also use the API Swagger: <https://us2.app.sysdig.com/secure/swagger.html>