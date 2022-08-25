package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
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
  },
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
  },
  "profilingDetectionEvents": {
    "countBySeverity": {
      "1": 0,
      "2": 0,
      "3": 0,
      "4": 0,
      "5": 0,
      "6": 0,
      "7": 0
    }
  },
  "hostScanningEvents": {
    "countBySeverity": {
      "1": 0,
      "2": 0,
      "3": 0,
      "4": 0,
      "5": 0,
      "6": 0,
      "7": 0
    }
  },
  "benchmarkEvents": {
    "countBySeverity": {
      "1": 0,
      "2": 0,
      "3": 0,
      "4": 0,
      "5": 0,
      "6": 0,
      "7": 0
    }
  },
  "complianceEvents": {
    "countBySeverity": {
      "0": 280,
      "1": 0,
      "2": 0,
      "3": 0,
      "4": 12,
      "5": 0,
      "6": 0,
      "7": 166
    }
  },
  "cloudsecEvents": {
    "countBySeverity": {
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

type SecureEventCountsMap struct { // FIXME: see, if you change the order, you can mix-up events !!
	ScanningEventCountsMap           EventCountsMap `json:"scanningEvents"`
	PolicyEventCountsMap             EventCountsMap `json:"policyEvents"`
	ProfilingDetectionEventCountsMap EventCountsMap `json:"profilingDetectionEvents"`
	HostScanningEventCountsMap       EventCountsMap `json:"hostScanningEvents"`
	BenchmarkEventCountsMap          EventCountsMap `json:"benchmarkEvents"`
	ComplianceEventCountsMap         EventCountsMap `json:"complianceEvents"`
	CloudsecEventCountsMap           EventCountsMap `json:"cloudsecEvents"`
}

type EventCountsMap struct {
	EventsCount map[uint8]uint32 `json:"countBySeverity"`
}

const namespace = "sysdig_secure"
const secureEventCountsApi = "api/v1/secureEvents/count?from=1654074448000000000&to=1655284048000000000" // FIXME: need to render the dates

var (
	transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client = &http.Client{
		Transport: transport,
	}

	listenAddress = flag.String("web.listen-address", ":9100",
		"address to listen on for metrics")
	metricsPath = flag.String("web.metrics-path", "/metrics",
		"path under which to expose metrics")

	// Global metrics
	up = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "up"),
		"Was the last Sysdig Secure API query successful?",
		nil, nil,
	)

	// Secure event metrics
	scanningEvents = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "secure_events_scanning_total"),
		"How many scanning events have been generated (per severity).",
		[]string{"severity", "count"}, nil,
	)

	policyEvents = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "secure_events_policy_total"),
		"How many policy events have been generated (per severity).",
		[]string{"severity", "count"}, nil,
	)

	profilingDetectionEvents = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "secure_events_profiling_detection_total"),
		"How many profiling detection events have been generated (per severity).",
		[]string{"severity", "count"}, nil,
	)

	hostScanningEvents = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "secure_events_host_scanning_total"),
		"How many policy events have been generated (per severity).",
		[]string{"severity", "count"}, nil,
	)

	benchmarkEvents = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "secure_events_benchmark_total"),
		"How many policy events have been generated (per severity).",
		[]string{"severity", "count"}, nil,
	)

	complianceEvents = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "secure_events_compliance_total"),
		"How many policy events have been generated (per severity).",
		[]string{"severity", "count"}, nil,
	)

	cloudsecEvents = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "secure_events_cloudsec_total"),
		"How many policy events have been generated (per severity).",
		[]string{"severity", "count"}, nil, // FIXME: Goto func SendPrometheusMetrics() below, does it really match ?
	)
)

type Exporter struct {
	sysdigSecureEndpoint, sysdigSecureApiKey string
}

func NewExporter(sysdigSecureEndpoint string, sysdigSecureApiKey string) *Exporter {
	return &Exporter{
		sysdigSecureEndpoint: sysdigSecureEndpoint,
		sysdigSecureApiKey:   sysdigSecureApiKey,
	}
}

func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {
	ch <- policyEvents
	ch <- scanningEvents
	ch <- profilingDetectionEvents
	ch <- hostScanningEvents
	ch <- benchmarkEvents
	ch <- complianceEvents
	ch <- cloudsecEvents
}

func (e *Exporter) Collect(ch chan<- prometheus.Metric) {
	secureEventCountsMap, err := e.LoadSecureEventCountsMap()

	if err != nil {
		ch <- prometheus.MustNewConstMetric(
			up, prometheus.GaugeValue, 0,
		)
		log.Fatal(err)
		return
	}
	ch <- prometheus.MustNewConstMetric(
		up, prometheus.GaugeValue, 1,
	)

	e.SendPrometheusMetrics(secureEventCountsMap, ch) // TODO: add other maps later here
}

func (e *Exporter) LoadSecureEventCountsMap() (SecureEventCountsMap, error) {
	// Load secure events
	req, err := http.NewRequest("GET", e.sysdigSecureEndpoint+secureEventCountsApi, nil)
	if err != nil { // FIXME: add funct checkErr()
		log.Fatal(err)
	}

	req.Header.Set("Authorization", "BEARER "+e.sysdigSecureApiKey)
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	body, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		log.Fatal(err)
	}

	var secureEventCountsMap SecureEventCountsMap // FIXME: a top-level variable, really ?
	err = json.Unmarshal(body, &secureEventCountsMap)
	if err != nil {
		log.Fatal(err)
	}

	return secureEventCountsMap, nil
}

func (e *Exporter) SendPrometheusMetrics(secureEventCountsMap SecureEventCountsMap, ch chan<- prometheus.Metric) {
	for pr, c := range secureEventCountsMap.PolicyEventCountsMap.EventsCount {
		ch <- prometheus.MustNewConstMetric(
			policyEvents, prometheus.GaugeValue, pr, c,
		)
	}
}

func main() {
	flag.Parse()

	// TODO: add config file parsing

	sysdigSecureEndpoint := os.Getenv("SYSDIG_SECURE_ENDPOINT")
	sysdigSecureApiKey := os.Getenv("SYSDIG_SECURE_API_KEY")

	exporter := NewExporter(sysdigSecureEndpoint, sysdigSecureApiKey)
	prometheus.MustRegister(exporter)

	log.SetLevel(log.DebugLevel) // FIXME: only for testing !!

	log.Info("Using Sysdig Secure endpoint: ", sysdigSecureEndpoint)

	//exporter.Collect() // FIXME: only for testing !!

	http.Handle(*metricsPath, promhttp.Handler())
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>
		<head><title>Sysdig Secure Exporter</title></head>
		<body>
		<h1>Sysdig Secure Exporter</h1>
		<p><a href='` + *metricsPath + `'></a></p>
		</body>
		</html>`))
	})

	log.Fatal(http.ListenAndServe(*listenAddress, nil))
}
