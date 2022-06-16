package main

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/joho/godotenv"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/text/number"
)


const namespace := "sysdig_secure"
const secureEventsApi := "api/v1/secureEvents/"

var (
	//Metrics
	scanningEvents := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "events_scanning_total"),
		"How many scanning events have been generated (per severity).",
		[]string{"severity"}, nil
	)

	policyEvents := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "events_policy_total"),
		"How many policy events have been generated (per severity).",
		[]string{"severity"}, nil
	)
)

type Exporter struct {
	sysdigSecureEndpoint, sysdigSecureApiKey string
}

func NewExporter(sysdigSecureEndpoint string, sysdigSecureApiKey string) *Exporter {
	return &Exporter{
		sysdigSecureEndpoint: sysdigSecureEndpoint,
		sysdigSecureApiKey: sysdigSecureApiKey
	}
}

func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {
	ch <- policyEvents
	ch <- scanningEvents
}

func (e *Exporter) Collect(ch chan<- prometheus.Metric) {
}

func main() {
	flag.Parse()
}

