package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"time"

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

type SecureEventCountsMatrix struct { // FIXME: see, if you change the order, you can mix-up events !!
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
      "key": "artifactory.datapwn.com/docker-io-remote/fluxcd/helm-operator",
      "count": 8805,
      "label": "container.image.repo"
    },
    {
      "key": "artifactory.datapwn.com/docker-io-remote/mongo",
      "count": 1693,
      "label": "container.image.repo"
    },
    {
      "key": "artifactory.datapwn.com/tlnd-docker-prod/company/sandbox/infra-azure",
      "count": 1535,
      "label": "container.image.repo"
    },
    {
      "key": "artifactory.datapwn.com/tlnd-docker-prod/company/sandbox/infra-aws",
      "count": 418,
      "label": "container.image.repo"
    },
    {
      "key": "artifactory.datapwn.com/tlnd-docker-prod/company/management-console/bookkeeper_mon",
      "count": 192,
      "label": "container.image.repo"
    }
  ],
  "kubernetes.cluster.name": [
    {
      "key": "prod-eu-app",
      "count": 3557,
      "label": "kubernetes.cluster.name"
    },
    {
      "key": "prod-us-app",
      "count": 3429,
      "label": "kubernetes.cluster.name"
    },
    {
      "key": "prod-apac-app",
      "count": 2844,
      "label": "kubernetes.cluster.name"
    },
    {
      "key": "prod-au-app",
      "count": 2733,
      "label": "kubernetes.cluster.name"
    },
    {
      "key": "at-app",
      "count": 263,
      "label": "kubernetes.cluster.name"
    }
  ],
  "kubernetes.namespace.name": [
    {
      "key": "app",
      "count": 10732,
      "label": "kubernetes.namespace.name"
    },
    {
      "key": "etcd",
      "count": 1583,
      "label": "kubernetes.namespace.name"
    },
    {
      "key": "backend",
      "count": 467,
      "label": "kubernetes.namespace.name"
    },
    {
      "key": "kube-system",
      "count": 25,
      "label": "kubernetes.namespace.name"
    },
    {
      "key": "minio",
      "count": 6,
      "label": "kubernetes.namespace.name"
    }
  ],
  "kubernetes.node.name": [
    {
      "key": "ip-10-86-183-68.eu-central-1.compute.internal",
      "count": 2282,
      "label": "kubernetes.node.name"
    },
    {
      "key": "ip-10-136-20-62.ap-southeast-2.compute.internal",
      "count": 2247,
      "label": "kubernetes.node.name"
    },
    {
      "key": "ip-10-89-50-175.ap-northeast-1.compute.internal",
      "count": 2211,
      "label": "kubernetes.node.name"
    },
    {
      "key": "ip-10-86-20-189.ec2.internal",
      "count": 1918,
      "label": "kubernetes.node.name"
    },
    {
      "key": "ip-10-86-37-223.ec2.internal",
      "count": 887,
      "label": "kubernetes.node.name"
    }
  ],
  "mitre": [
    {
      "key": "MITRE_TA0003_persistence",
      "count": 11122,
      "label": "ruleTags"
    },
    {
      "key": "MITRE_TA0005_defense_evasion",
      "count": 11098,
      "label": "ruleTags"
    },
    {
      "key": "MITRE_TA0004_privilege_escalation",
      "count": 36,
      "label": "ruleTags"
    },
    {
      "key": "MITRE_TA0002_execution",
      "count": 12,
      "label": "ruleTags"
    },
    {
      "key": "MITRE_TA0001_initial_access",
      "count": 8,
      "label": "ruleTags"
    }
  ],
  "ruleName": [
    {
      "key": "Write below root",
      "count": 11053,
      "label": "ruleName"
    },
    {
      "key": "Drift Detection",
      "count": 1669,
      "label": "ruleName"
    },
    {
      "key": "Write below etc",
      "count": 45,
      "label": "ruleName"
    },
    {
      "key": "Mount Launched in Privileged Container",
      "count": 26,
      "label": "ruleName"
    },
    {
      "key": "Launch Package Management Process in Container",
      "count": 24,
      "label": "ruleName"
    }
  ],
  "workload": [
    {
      "key": "app-flux-helm-operator",
      "count": 8755,
      "label": "kubernetes.deployment.name"
    },
    {
      "key": "tmc-data-cleanup-artifacts",
      "count": 1693,
      "label": "kubernetes.cronJob.name"
    },
    {
      "key": "tmc-data-cleanup-artifacts-27723630",
      "count": 1693,
      "label": "kubernetes.job.name"
    },
    {
      "key": "etcd-minio-backup-company-etcd-backup",
      "count": 1583,
      "label": "kubernetes.cronJob.name"
    },
    {
      "key": "tmc-ghostmonitor-cronjob",
      "count": 239,
      "label": "kubernetes.cronJob.name"
    }
  ]
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
	apiTimeWindow = flag.String("api.time-window", "24h",
		"time period for api historical data")
	apiStatRows = flag.Int("api.stat-rows", 5,
		"number of rows for api statistics")
	logLevel = flag.String("log.level", "info",
		"log level")

	// API parameters
	secureEventCountsApi   string
	secureEventTopStatsApi string

	// Global metrics
	up = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "up"),
		"Was the last Sysdig Secure API query successful ?",
		nil, nil,
	)

	// Secure event count metrics
	scanningEventCounts = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "scanning_events_total"),
		"How many scanning secure events have been generated (per severity) ?",
		[]string{"severity"}, nil,
	)

	policyEventCounts = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "policy_events_total"),
		"How many policy secure events have been generated (per severity) ?",
		[]string{"severity"}, nil,
	)

	profilingDetectionEventCounts = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "profiling_detection_events_total"),
		"How many profiling detection secure events have been generated (per severity) ?",
		[]string{"severity"}, nil,
	)

	hostScanningEventCounts = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "host_scanning_events_total"),
		"How many host scanning secure events have been generated (per severity) ?",
		[]string{"severity"}, nil,
	)

	benchmarkEventCounts = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "benchmark_events_total"),
		"How many benchmark secure events have been generated (per severity) ?",
		[]string{"severity"}, nil,
	)

	complianceEventCounts = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "compliance_events_total"),
		"How many compliance secure events have been generated (per severity) ?",
		[]string{"severity"}, nil,
	)

	cloudsecEventCounts = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "cloudsec_events_total"),
		"How many cloudsec secure events have been generated (per severity) ?",
		[]string{"severity"}, nil, // FIXME: Goto func SendPrometheusMetrics() below, does it really match ?
	)

	// Secure event top stat metrics
	imageEventTopStats = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "top_image_events_total"),
		"What are the top generated secure events (per container image and label) ?",
		[]string{"image", "label"}, nil,
	)

	clusterEventTopStats = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "top_cluster_events_total"),
		"What are the top generated secure events (per kubernetes cluster and label) ?",
		[]string{"cluster", "label"}, nil,
	)

	namespaceEventTopStats = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "top_namespace_events_total"),
		"What are the top generated secure events (per kubernetes namespace and label) ?",
		[]string{"namespace", "label"}, nil,
	)

	nodeEventTopStats = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "top_node_events_total"),
		"What are the top generated secure events (per kubernetes node and label) ?",
		[]string{"node", "label"}, nil,
	)

	mitreEventTopStats = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "top_mitre_events_total"),
		"What are the top generated secure events (per mitre and label) ?",
		[]string{"mitre", "label"}, nil,
	)

	ruleEventTopStats = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "top_rule_events_total"),
		"What are the top generated secure events (per rule and label) ?",
		[]string{"rule", "label"}, nil,
	)

	workloadEventTopStats = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "top_workload_events_total"),
		"What are the top generated secure events (per workload and label) ?",
		[]string{"workload", "label"}, nil,
	)
)

type Exporter struct {
	sysdigSecureEndpoint, sysdigSecureApiKey string
	sysdigSecureApiTimeWindow                time.Duration
	sysdigSecureApiStatRows                  uint8
}

func NewExporter(sysdigSecureEndpoint string, sysdigSecureApiKey string, sysdigSecureApiTimeWindow time.Duration, sysdigSecureApiStatRows uint8) *Exporter {
	return &Exporter{
		sysdigSecureEndpoint:      sysdigSecureEndpoint,
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
	sysdigSecureApiTimeTo := time.Now() // TODO: move this chunk to a funct ?
	sysdigSecureApiTimeFrom := sysdigSecureApiTimeTo.Add(-e.sysdigSecureApiTimeWindow)

	secureEventCountsApi = fmt.Sprintf("api/v1/secureEvents/count?from=%d&to=%d", uint64(sysdigSecureApiTimeFrom.UnixNano()), uint64(sysdigSecureApiTimeTo.UnixNano()))
	secureEventTopStatsApi = fmt.Sprintf("api/v1/secureEvents/topStats?from=%d&to=%d&rows=%d", uint64(sysdigSecureApiTimeFrom.UnixNano()), uint64(sysdigSecureApiTimeTo.UnixNano()), e.sysdigSecureApiStatRows)

	// Load secure event counts
	secureEventCountsMatrix, err := e.LoadSecureEventCountsMatrix()

	if err != nil {
		ch <- prometheus.MustNewConstMetric(
			up, prometheus.GaugeValue, 0,
		)
		log.Fatal(err)
		return
	}

	// Load secure event top stats
	SecureEventTopStatsMatrix, err := e.LoadSecureEventTopStatsMatrix()

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

	e.SendPrometheusMetrics(secureEventCountsMatrix, SecureEventTopStatsMatrix, ch)
}

func (e *Exporter) LoadSecureEventCountsMatrix() (SecureEventCountsMatrix, error) {
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

	var secureEventCountsMatrix SecureEventCountsMatrix // FIXME: a top-level variable ?
	err = json.Unmarshal(body, &secureEventCountsMatrix)
	if err != nil {
		log.Fatal(err)
	}

	return secureEventCountsMatrix, nil
}

func (e *Exporter) LoadSecureEventTopStatsMatrix() (SecureEventTopStatsMatrix, error) {
	req, err := http.NewRequest("GET", e.sysdigSecureEndpoint+secureEventTopStatsApi, nil) // TODO: move into a common funct ?
	if err != nil {                                                                        // FIXME: add funct checkErr()
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

	var secureEventTopStatsMatrix SecureEventTopStatsMatrix // FIXME: a top-level variable ?
	err = json.Unmarshal(body, &secureEventTopStatsMatrix)
	if err != nil {
		log.Fatal(err)
	}

	return secureEventTopStatsMatrix, nil
}

func (e *Exporter) SendPrometheusMetrics(secureEventCountsMatrix SecureEventCountsMatrix, secureEventTopStatsMatrix SecureEventTopStatsMatrix, ch chan<- prometheus.Metric) {
	// Push secure event count metrics
	for pr, c := range secureEventCountsMatrix.PolicyEventCountsMap.EventsCount {
		prio := strconv.Itoa(int(pr))
		ch <- prometheus.MustNewConstMetric(
			policyEventCounts, prometheus.GaugeValue, float64(c), prio,
		)
	}

	for pr, c := range secureEventCountsMatrix.ScanningEventCountsMap.EventsCount {
		prio := strconv.Itoa(int(pr))
		ch <- prometheus.MustNewConstMetric(
			scanningEventCounts, prometheus.GaugeValue, float64(c), prio,
		)
	}

	for pr, c := range secureEventCountsMatrix.ProfilingDetectionEventCountsMap.EventsCount {
		prio := strconv.Itoa(int(pr))
		ch <- prometheus.MustNewConstMetric(
			profilingDetectionEventCounts, prometheus.GaugeValue, float64(c), prio,
		)
	}

	for pr, c := range secureEventCountsMatrix.HostScanningEventCountsMap.EventsCount {
		prio := strconv.Itoa(int(pr))
		ch <- prometheus.MustNewConstMetric(
			hostScanningEventCounts, prometheus.GaugeValue, float64(c), prio,
		)
	}

	for pr, c := range secureEventCountsMatrix.BenchmarkEventCountsMap.EventsCount {
		prio := strconv.Itoa(int(pr))
		ch <- prometheus.MustNewConstMetric(
			benchmarkEventCounts, prometheus.GaugeValue, float64(c), prio,
		)
	}

	for pr, c := range secureEventCountsMatrix.ComplianceEventCountsMap.EventsCount {
		prio := strconv.Itoa(int(pr))
		ch <- prometheus.MustNewConstMetric(
			complianceEventCounts, prometheus.GaugeValue, float64(c), prio,
		)
	}

	for pr, c := range secureEventCountsMatrix.CloudsecEventCountsMap.EventsCount {
		prio := strconv.Itoa(int(pr))
		ch <- prometheus.MustNewConstMetric(
			cloudsecEventCounts, prometheus.GaugeValue, float64(c), prio, // FIXME: maybe an arch-agnostic funct like float() would be better ?
		)
	}

	// Push secure event top stat metrics
	for c := 0; c < int(e.sysdigSecureApiStatRows); c++ {
		key := secureEventTopStatsMatrix.ImageEventTopStatsArray[c].EventsKey
		cnt := secureEventTopStatsMatrix.ImageEventTopStatsArray[c].EventsCount
		lbl := secureEventTopStatsMatrix.ImageEventTopStatsArray[c].EventsLabel
		ch <- prometheus.MustNewConstMetric(
			imageEventTopStats, prometheus.GaugeValue, float64(cnt), key, lbl,
		)
	}

	for c := 0; c < int(e.sysdigSecureApiStatRows); c++ {
		key := secureEventTopStatsMatrix.ClusterEventTopStatsArray[c].EventsKey
		cnt := secureEventTopStatsMatrix.ClusterEventTopStatsArray[c].EventsCount
		lbl := secureEventTopStatsMatrix.ClusterEventTopStatsArray[c].EventsLabel
		ch <- prometheus.MustNewConstMetric(
			clusterEventTopStats, prometheus.GaugeValue, float64(cnt), key, lbl,
		)
	}

	for c := 0; c < int(e.sysdigSecureApiStatRows); c++ {
		key := secureEventTopStatsMatrix.NamespaceEventTopStatsArray[c].EventsKey
		cnt := secureEventTopStatsMatrix.NamespaceEventTopStatsArray[c].EventsCount
		lbl := secureEventTopStatsMatrix.NamespaceEventTopStatsArray[c].EventsLabel
		ch <- prometheus.MustNewConstMetric(
			namespaceEventTopStats, prometheus.GaugeValue, float64(cnt), key, lbl,
		)
	}

	for c := 0; c < int(e.sysdigSecureApiStatRows); c++ {
		key := secureEventTopStatsMatrix.NodeEventTopStatsArray[c].EventsKey
		cnt := secureEventTopStatsMatrix.NodeEventTopStatsArray[c].EventsCount
		lbl := secureEventTopStatsMatrix.NodeEventTopStatsArray[c].EventsLabel
		ch <- prometheus.MustNewConstMetric(
			nodeEventTopStats, prometheus.GaugeValue, float64(cnt), key, lbl,
		)
	}

	for c := 0; c < int(e.sysdigSecureApiStatRows); c++ {
		key := secureEventTopStatsMatrix.MitreEventTopStatsArray[c].EventsKey
		cnt := secureEventTopStatsMatrix.MitreEventTopStatsArray[c].EventsCount
		lbl := secureEventTopStatsMatrix.MitreEventTopStatsArray[c].EventsLabel
		ch <- prometheus.MustNewConstMetric(
			mitreEventTopStats, prometheus.GaugeValue, float64(cnt), key, lbl,
		)
	}

	for c := 0; c < int(e.sysdigSecureApiStatRows); c++ {
		key := secureEventTopStatsMatrix.RuleNameEventTopStatsArray[c].EventsKey
		cnt := secureEventTopStatsMatrix.RuleNameEventTopStatsArray[c].EventsCount
		lbl := secureEventTopStatsMatrix.RuleNameEventTopStatsArray[c].EventsLabel
		ch <- prometheus.MustNewConstMetric(
			ruleEventTopStats, prometheus.GaugeValue, float64(cnt), key, lbl,
		)
	}

	for c := 0; c < int(e.sysdigSecureApiStatRows); c++ {
		key := secureEventTopStatsMatrix.WorkloadEventTopStatsArray[c].EventsKey
		cnt := secureEventTopStatsMatrix.WorkloadEventTopStatsArray[c].EventsCount
		lbl := secureEventTopStatsMatrix.WorkloadEventTopStatsArray[c].EventsLabel
		ch <- prometheus.MustNewConstMetric(
			workloadEventTopStats, prometheus.GaugeValue, float64(cnt), key, lbl,
		)
	}
}

func main() {
	flag.Parse()

	// TODO: add config file parsing

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
		log.Fatal("Supported log levels: \"trace\", \"debug\", \"info\", \"warn\", \"error\", \"fatal\", and \"panic\".")
	}

	sysdigSecureEndpoint := os.Getenv("SYSDIG_SECURE_ENDPOINT") // FIXME: must use flags + a top level variable ?
	sysdigSecureApiKey := os.Getenv("SYSDIG_SECURE_API_KEY")

	sysdigSecureApiTimeWindow, err := time.ParseDuration(*apiTimeWindow) // FIXME: something better than pointers
	if err != nil {
		log.Fatal(err)
	}

	sysdigSecureApiStatRows := uint8(*apiStatRows)

	log.Infof("Using Sysdig Secure API endpoint: %s", sysdigSecureEndpoint)
	log.Infof("Using API time window: %d hours", uint16(sysdigSecureApiTimeWindow.Hours()))

	exporter := NewExporter(sysdigSecureEndpoint, sysdigSecureApiKey, sysdigSecureApiTimeWindow, sysdigSecureApiStatRows)
	prometheus.MustRegister(exporter)

	http.Handle(*metricsPath, promhttp.Handler())
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>
		<head><title>Sysdig Secure Prometheus Exporter</title></head>
		<body>
		<h1>Sysdig Secure Prometheus Exporter</h1>
		<p><a href='` + *metricsPath + `'></a></p>
		</body>
		</html>`))
	})

	log.Fatal(http.ListenAndServe(*listenAddress, nil))
}
