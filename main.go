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

/*
{
  "scanningEvents": {
    "countBySeverity": {
      "0": 90,
      "1": 0,
      "2": 0,
      "3": 0,
      "4": 0,
      "5": 0,
      "6": 0,
      "7": 0
    }
  }
}
*/

type scanningEventCountList struct {
	eventCounts []scanningEventCount	`json:"countBySeverity"`
}

type scanningEventCount struct {
	severity0	number	`json:"0"`
	severity1	number	`json:"1"`
	severity2	number	`json:"2"`
	severity3	number	`json:"3"`
	severity4	number	`json:"4"`
	severity5	number	`json:"5"`
	severity6	number	`json:"6"`
	severity7	number	`json:"7"`
}

/*
{
  "policyEvents": {
    "countBySeverity": {
      "0": 303,
      "1": 0,
      "2": 0,
      "3": 178,
      "4": 189923,
      "5": 837,
      "6": 0,
      "7": 0
    }
  }
}
*/

type policyEventCountList struct {
	eventCounts []policyEventCount	`json:"countBySeverity"`
}

type policyEventCount struct {
	severity0	number	`json:"0"`
	severity1	number	`json:"1"`
	severity2	number	`json:"2"`
	severity3	number	`json:"3"`
	severity4	number	`json:"4"`
	severity5	number	`json:"5"`
	severity6	number	`json:"6"`
	severity7	number	`json:"7"`
}

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

