package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
)

/*
{
  "scanningEvents": {
    "countBySeverity": {
      "0": 101,
      "1": 17,
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
      "0": 706,
      "1": 0,
      "2": 0,
      "3": 230,
      "4": 829,
      "5": 13765,
      "6": 0,
      "7": 0
    }
  },
  ...
}
*/

type SecureEventCountsMatrix struct {
	ScanningEventCountsMap           EventCountsMap `json:"scanningEvents,omitempty"`
	PolicyEventCountsMap             EventCountsMap `json:"policyEvents,omitempty"`
	ProfilingDetectionEventCountsMap EventCountsMap `json:"profilingDetectionEvents,omitempty"`
	HostScanningEventCountsMap       EventCountsMap `json:"hostScanningEvents,omitempty"`
	BenchmarkEventCountsMap          EventCountsMap `json:"benchmarkEvents,omitempty"`
	ComplianceEventCountsMap         EventCountsMap `json:"complianceEvents,omitempty"`
	CloudsecEventCountsMap           EventCountsMap `json:"cloudsecEvents,omitempty"`
}

type EventCountsMap struct {
	EventsCount map[uint8]uint32 `json:"countBySeverity,omitempty"`
}

/*
{
  "container.image.repo": [
    {
      "key": "ubuntu",
      "count": 931,
      "label": "container.image.repo"
    },
    {
      "key": "traefik",
      "count": 107,
      "label": "container.image.repo"
    },
    ...
  ],
  "kubernetes.cluster.name": [
    {
      "key": "prod-app",
      "count": 3557,
      "label": "kubernetes.cluster.name"
    },
    {
      "key": "staging-app",
      "count": 3429,
      "label": "kubernetes.cluster.name"
    },
    ...
  ],
  ...
}
*/

type SecureEventTopStatsMatrix struct {
	ImageEventTopStatsArray     []EventTopStatsMap `json:"container.image.repo,omitempty"`
	ClusterEventTopStatsArray   []EventTopStatsMap `json:"kubernetes.cluster.name,omitempty"`
	NamespaceEventTopStatsArray []EventTopStatsMap `json:"kubernetes.namespace.name,omitempty"`
	NodeEventTopStatsArray      []EventTopStatsMap `json:"kubernetes.node.name,omitempty"`
	MitreEventTopStatsArray     []EventTopStatsMap `json:"mitre,omitempty"`
	RuleNameEventTopStatsArray  []EventTopStatsMap `json:"ruleName,omitempty"`
	WorkloadEventTopStatsArray  []EventTopStatsMap `json:"workload,omitempty"`
}

type EventTopStatsMap struct {
	EventsKey   string `json:"key,omitempty"`
	EventsCount uint32 `json:"count,omitempty"`
	EventsLabel string `json:"label,omitempty"`
}

const namespace = "sysdig_secure" // CHECKME: can we get multi-tenant enents, like prod, staging ..etc ?

var (
	transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	client    = &http.Client{Transport: transport}

	// Flags
	apiTimeWindow = flag.String("api.time-window", "24h", "time period for event count apis")
	apiStatRows   = flag.Int("api.stat-rows", 5, "number of rows in top stat apis")
	envFile       = flag.String("config.env-file", "", "environment file path")
	logLevel      = flag.String("config.log-level", "info", "logging level")
	listenAddress = flag.String("web.listen-address", ":9100", "address to listen on for metrics")
	metricsPath   = flag.String("web.metrics-path", "/metrics", "path under which to expose metrics")

	// API paths
	secureEventCountsApi   string
	secureEventTopStatsApi string

	// Global metrics
	up = prometheus.NewDesc(prometheus.BuildFQName(namespace, "", "up"), "Was the last API query successful ?", nil, nil)

	// Secure event count metrics
	scanningEventCounts = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "scanning_events_total"), "What is the count of scanning events (per severity) ?", []string{"severity"}, nil)
	policyEventCounts = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "policy_events_total"), "What is the count of policy events (per severity) ?", []string{"severity"}, nil)
	profilingDetectionEventCounts = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "profiling_detection_events_total"), "What is the count of profiling detection events (per severity) ?", []string{"severity"}, nil)
	hostScanningEventCounts = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "host_scanning_events_total"), "What is the count of host scanning events (per severity) ?", []string{"severity"}, nil)
	benchmarkEventCounts = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "benchmark_events_total"), "What is the count of benchmark events (per severity) ?", []string{"severity"}, nil)
	complianceEventCounts = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "compliance_events_total"), "What is the count of compliance events (per severity) ?", []string{"severity"}, nil)
	cloudsecEventCounts = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "cloudsec_events_total"), "What is the count of cloudsec events (per severity) ?", []string{"severity"}, nil)

	// Secure event top stat metrics
	imageEventTopStats = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "top_image_events_total"), "What are the top column values and counts of events by container image (per image and label) ?", []string{"image", "label"}, nil)
	clusterEventTopStats = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "top_cluster_events_total"), "What are the top column values and counts of events by kubernetes cluster (per cluster and label) ?", []string{"cluster", "label"}, nil)
	namespaceEventTopStats = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "top_namespace_events_total"), "What are the top column values and counts of events by kubernetes namespace (per namespace and label) ?", []string{"namespace", "label"}, nil)
	nodeEventTopStats = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "top_node_events_total"), "What are the top column values and counts of events by kubernetes node (per node and label) ?", []string{"node", "label"}, nil)
	mitreEventTopStats = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "top_mitre_events_total"), "What are the top column values and counts of events by mitre (per mitre and label) ?", []string{"mitre", "label"}, nil)
	ruleEventTopStats = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "top_rule_events_total"), "What are the top column values and counts of events by rule name (per rule and label) ?", []string{"rule", "label"}, nil)
	workloadEventTopStats = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "top_workload_events_total"), "What are the top column values and counts of events by workload (per workload and label) ?", []string{"workload", "label"}, nil)
)

type Exporter struct {
	sysdigSecureApiEndpoint, sysdigSecureApiKey string
	sysdigSecureApiTimeWindow                   time.Duration
	sysdigSecureApiStatRows                     uint8
}

func checkErr(err error, ch chan<- prometheus.Metric) {
	if err != nil {
		// Inform scrape has failed, if channel is given
		if ch != nil {
			ch <- prometheus.MustNewConstMetric(up, prometheus.GaugeValue, 0)
		}
		// Log error
		log.Fatal(err)
	}
}

func NewExporter(sysdigSecureApiEndpoint string, sysdigSecureApiKey string, sysdigSecureApiTimeWindow time.Duration, sysdigSecureApiStatRows uint8) *Exporter {
	return &Exporter{
		sysdigSecureApiEndpoint:   sysdigSecureApiEndpoint,
		sysdigSecureApiKey:        sysdigSecureApiKey,
		sysdigSecureApiTimeWindow: sysdigSecureApiTimeWindow,
		sysdigSecureApiStatRows:   sysdigSecureApiStatRows,
	}
}

func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {
	// Secure event count metrics
	ch <- policyEventCounts
	ch <- scanningEventCounts
	ch <- profilingDetectionEventCounts
	ch <- hostScanningEventCounts
	ch <- benchmarkEventCounts
	ch <- complianceEventCounts
	ch <- cloudsecEventCounts

	// Secure event top stat metrics
	ch <- imageEventTopStats
	ch <- clusterEventTopStats
	ch <- namespaceEventTopStats
	ch <- nodeEventTopStats
	ch <- mitreEventTopStats
	ch <- ruleEventTopStats
	ch <- workloadEventTopStats
}

func (e *Exporter) Collect(ch chan<- prometheus.Metric) {
	// Calculate the 'from' and 'to' timings
	sysdigSecureApiTimeTo := time.Now()
	sysdigSecureApiTimeFrom := sysdigSecureApiTimeTo.Add(-e.sysdigSecureApiTimeWindow)

	// Format API paths
	secureEventCountsApi = fmt.Sprintf("api/v1/secureEvents/count?from=%d&to=%d", uint64(sysdigSecureApiTimeFrom.UnixNano()), uint64(sysdigSecureApiTimeTo.UnixNano()))
	secureEventTopStatsApi = fmt.Sprintf("api/v1/secureEvents/topStats?from=%d&to=%d&rows=%d", uint64(sysdigSecureApiTimeFrom.UnixNano()), uint64(sysdigSecureApiTimeTo.UnixNano()), e.sysdigSecureApiStatRows)

	// Load secure event counts
	secureEventCountsMatrix, err := e.LoadSecureEventCountsMatrix()
	checkErr(err, ch)

	// Load secure event top stats
	SecureEventTopStatsMatrix, err := e.LoadSecureEventTopStatsMatrix()
	checkErr(err, ch)

	// Inform scrape has succeeded
	ch <- prometheus.MustNewConstMetric(
		up, prometheus.GaugeValue, 1,
	)

	e.SendPrometheusMetrics(secureEventCountsMatrix, SecureEventTopStatsMatrix, ch)
}

func (e *Exporter) LoadSecureEventCountsMatrix() (SecureEventCountsMatrix, error) {
	// Setup HTTP request
	req, err := http.NewRequest("GET", e.sysdigSecureApiEndpoint+secureEventCountsApi, nil)
	checkErr(err, nil)

	// Authenticate
	req.Header.Set("Authorization", "BEARER "+e.sysdigSecureApiKey)
	resp, err := client.Do(req)
	checkErr(err, nil)

	// Check status code
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		log.Fatal(resp.Status)
	}

	// Read response body
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	checkErr(err, nil)

	// Unmarshall secure event counts json
	var secureEventCountsMatrix SecureEventCountsMatrix
	err = json.Unmarshal(body, &secureEventCountsMatrix)
	checkErr(err, nil)

	return secureEventCountsMatrix, nil
}

func (e *Exporter) LoadSecureEventTopStatsMatrix() (SecureEventTopStatsMatrix, error) {
	// Setup HTTP request
	req, err := http.NewRequest("GET", e.sysdigSecureApiEndpoint+secureEventTopStatsApi, nil)
	checkErr(err, nil)

	// Authenticate
	req.Header.Set("Authorization", "BEARER "+e.sysdigSecureApiKey)
	resp, err := client.Do(req)
	checkErr(err, nil)

	// Check status code
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		log.Fatal(resp.Status)
	}

	// Read response body
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	checkErr(err, nil)

	// Unmarshall secure event top stats json
	var secureEventTopStatsMatrix SecureEventTopStatsMatrix
	err = json.Unmarshal(body, &secureEventTopStatsMatrix)
	checkErr(err, nil)

	return secureEventTopStatsMatrix, nil
}

func (e *Exporter) SendPrometheusMetrics(secureEventCountsMatrix SecureEventCountsMatrix, secureEventTopStatsMatrix SecureEventTopStatsMatrix, ch chan<- prometheus.Metric) {
	// Push secure event count metrics
	for pr, c := range secureEventCountsMatrix.PolicyEventCountsMap.EventsCount {
		prio := strconv.Itoa(int(pr))
		ch <- prometheus.MustNewConstMetric(policyEventCounts, prometheus.GaugeValue, float64(c), prio)
	}

	for pr, c := range secureEventCountsMatrix.ScanningEventCountsMap.EventsCount {
		prio := strconv.Itoa(int(pr))
		ch <- prometheus.MustNewConstMetric(scanningEventCounts, prometheus.GaugeValue, float64(c), prio)
	}

	for pr, c := range secureEventCountsMatrix.ProfilingDetectionEventCountsMap.EventsCount {
		prio := strconv.Itoa(int(pr))
		ch <- prometheus.MustNewConstMetric(profilingDetectionEventCounts, prometheus.GaugeValue, float64(c), prio)
	}

	for pr, c := range secureEventCountsMatrix.HostScanningEventCountsMap.EventsCount {
		prio := strconv.Itoa(int(pr))
		ch <- prometheus.MustNewConstMetric(hostScanningEventCounts, prometheus.GaugeValue, float64(c), prio)
	}

	for pr, c := range secureEventCountsMatrix.BenchmarkEventCountsMap.EventsCount {
		prio := strconv.Itoa(int(pr))
		ch <- prometheus.MustNewConstMetric(benchmarkEventCounts, prometheus.GaugeValue, float64(c), prio)
	}

	for pr, c := range secureEventCountsMatrix.ComplianceEventCountsMap.EventsCount {
		prio := strconv.Itoa(int(pr))
		ch <- prometheus.MustNewConstMetric(complianceEventCounts, prometheus.GaugeValue, float64(c), prio)
	}

	for pr, c := range secureEventCountsMatrix.CloudsecEventCountsMap.EventsCount {
		prio := strconv.Itoa(int(pr))
		ch <- prometheus.MustNewConstMetric(cloudsecEventCounts, prometheus.GaugeValue, float64(c), prio)
	}

	// Push secure event top stat metrics
	for k, st := range secureEventTopStatsMatrix.ImageEventTopStatsArray {
		_ = k
		key := st.EventsKey
		cnt := st.EventsCount
		lbl := st.EventsLabel
		ch <- prometheus.MustNewConstMetric(imageEventTopStats, prometheus.GaugeValue, float64(cnt), key, lbl)
	}

	for k, st := range secureEventTopStatsMatrix.ClusterEventTopStatsArray {
		_ = k
		key := st.EventsKey
		cnt := st.EventsCount
		lbl := st.EventsLabel
		ch <- prometheus.MustNewConstMetric(clusterEventTopStats, prometheus.GaugeValue, float64(cnt), key, lbl)
	}

	for k, st := range secureEventTopStatsMatrix.NamespaceEventTopStatsArray {
		_ = k
		key := st.EventsKey
		cnt := st.EventsCount
		lbl := st.EventsLabel
		ch <- prometheus.MustNewConstMetric(namespaceEventTopStats, prometheus.GaugeValue, float64(cnt), key, lbl)
	}

	for k, st := range secureEventTopStatsMatrix.NodeEventTopStatsArray {
		_ = k
		key := st.EventsKey
		cnt := st.EventsCount
		lbl := st.EventsLabel
		ch <- prometheus.MustNewConstMetric(nodeEventTopStats, prometheus.GaugeValue, float64(cnt), key, lbl)
	}

	for k, st := range secureEventTopStatsMatrix.MitreEventTopStatsArray {
		_ = k
		key := st.EventsKey
		cnt := st.EventsCount
		lbl := st.EventsLabel
		ch <- prometheus.MustNewConstMetric(mitreEventTopStats, prometheus.GaugeValue, float64(cnt), key, lbl)
	}

	for k, st := range secureEventTopStatsMatrix.RuleNameEventTopStatsArray {
		_ = k
		key := st.EventsKey
		cnt := st.EventsCount
		lbl := st.EventsLabel
		ch <- prometheus.MustNewConstMetric(ruleEventTopStats, prometheus.GaugeValue, float64(cnt), key, lbl)
	}

	for k, st := range secureEventTopStatsMatrix.WorkloadEventTopStatsArray {
		_ = k
		key := st.EventsKey
		cnt := st.EventsCount
		lbl := st.EventsLabel
		ch <- prometheus.MustNewConstMetric(workloadEventTopStats, prometheus.GaugeValue, float64(cnt), key, lbl)
	}
}

func main() {
	flag.Parse()

	// Set logging level
	switch *logLevel {
	case "trace":
		log.SetLevel(log.TraceLevel)
	case "debug":
		log.SetLevel(log.DebugLevel)
	case "info":
		log.SetLevel(log.InfoLevel)
	case "warn":
		log.SetLevel(log.WarnLevel)
	case "error":
		log.SetLevel(log.ErrorLevel)
	case "fatal":
		log.SetLevel(log.FatalLevel)
	case "panic":
		log.SetLevel(log.PanicLevel)
	default:
		log.Warn("Unsupported log level, setting to \"info\" by default.")
	}

	// Parse environment variables from file
	envFilePath := *envFile
	if envFilePath != "" {
		err := godotenv.Load(envFilePath)
		if err != nil {
			log.Warnf("Could not load env file: '%s', assuming env variables are set.", envFilePath)
		}
	}

	// Parse environment variables from shell
	sysdigSecureApiEndpoint := os.Getenv("SYSDIG_SECURE_API_ENDPOINT")
	sysdigSecureApiKey := os.Getenv("SYSDIG_SECURE_API_KEY")
	if len(sysdigSecureApiEndpoint) == 0 {
		sysdigSecureApiEndpoint = "https://secure.sysdig.com/"
	}
	if len(sysdigSecureApiKey) == 0 {
		log.Warn("Could not read a Sysdig Secure API key, env variable SYSDIG_SECURE_API_KEY is empty.")
	}

	// Format API parameters
	sysdigSecureApiTimeWindow, err := time.ParseDuration(*apiTimeWindow)
	checkErr(err, nil)
	sysdigSecureApiStatRows := uint8(*apiStatRows)

	log.Infof("Using Sysdig Secure API endpoint: %s", sysdigSecureApiEndpoint)
	log.Infof("Using API time window (diff. btw 'from' and 'to'): %d hours", uint16(sysdigSecureApiTimeWindow.Hours()))

	// Setup the Prometheus exporter
	exporter := NewExporter(sysdigSecureApiEndpoint, sysdigSecureApiKey, sysdigSecureApiTimeWindow, sysdigSecureApiStatRows)
	prometheus.MustRegister(exporter)

	// Setup the Prometheus metrics endpoint
	http.Handle(*metricsPath, promhttp.Handler())
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>
<head><title>Sysdig Secure Prometheus Exporter</title></head>
<body>
<h1>A Prometheus Exporter for Sysdig Secure events</h1>
<p><a href='` + *metricsPath + `'></a></p>
</body>
</html>`))
	})

	log.Fatal(http.ListenAndServe(*listenAddress, nil))
}
