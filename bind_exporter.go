package main

import (
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"math"
	"net"
	"net/http"
	_ "net/http/pprof"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/log"
)

const (
	namespace = "bind"
	resolver  = "resolver"
	qryRTT    = "QryRTT"
)

var (
	bindMetrics = []string{}

	up = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "up"),
		"Was the Bind instance query successful?",
		nil, nil,
	)
	incomingQueries = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "incoming_queries_total"),
		"Number of incomming DNS queries.",
		[]string{"type"}, nil,
	)
	incomingRequests = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "incoming_requests_total"),
		"Number of incomming DNS requests.",
		[]string{"name"}, nil,
	)
	resolverCache = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, resolver, "cache_rrsets"),
		"Number of RRSets in Cache database.",
		[]string{"view", "type"}, nil,
	)
	resolverQueries = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, resolver, "queries_total"),
		"Number of outgoing DNS queries.",
		[]string{"view", "type"}, nil,
	)
	resolverQueryDuration = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, resolver, "query_duration_seconds"),
		"Resolver query round-trip time in seconds.",
		[]string{"view"}, nil,
	)
	resolverQueryErrors = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, resolver, "query_errors_total"),
		"Number of resolver queries failed.",
		[]string{"view", "error"}, nil,
	)
	resolverResponseErrors = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, resolver, "response_errors_total"),
		"Number of resolver reponse errors received.",
		[]string{"view", "error"}, nil,
	)
	resolverDNSSECSucess = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, resolver, "dnssec_validation_success_total"),
		"Number of DNSSEC validation attempts succeeded.",
		[]string{"view", "result"}, nil,
	)
	resolverMetricStats = map[string]*prometheus.Desc{
		"Lame": prometheus.NewDesc(
			prometheus.BuildFQName(namespace, resolver, "response_lame_total"),
			"Number of lame delegation responses received.",
			[]string{"view"}, nil,
		),
		"EDNS0Fail": prometheus.NewDesc(
			prometheus.BuildFQName(namespace, resolver, "query_edns0_errors_total"),
			"Number of EDNS(0) query errors.",
			[]string{"view"}, nil,
		),
		"Mismatch": prometheus.NewDesc(
			prometheus.BuildFQName(namespace, resolver, "response_mismatch_total"),
			"Number of mismatch responses received.",
			[]string{"view"}, nil,
		),
		"Retry": prometheus.NewDesc(
			prometheus.BuildFQName(namespace, resolver, "query_retries_total"),
			"Number of resolver query retries.",
			[]string{"view"}, nil,
		),
		"Truncated": prometheus.NewDesc(
			prometheus.BuildFQName(namespace, resolver, "response_truncated_total"),
			"Number of truncated responses received.",
			[]string{"view"}, nil,
		),
		"ValFail": prometheus.NewDesc(
			prometheus.BuildFQName(namespace, resolver, "dnssec_validation_errors_total"),
			"Number of DNSSEC validation attempt errors.",
			[]string{"view"}, nil,
		),
	}
	resolverLabelStats = map[string]*prometheus.Desc{
		"QueryAbort":    resolverQueryErrors,
		"QuerySockFail": resolverQueryErrors,
		"QueryTimeout":  resolverQueryErrors,
		"NXDOMAIN":      resolverResponseErrors,
		"SERVFAIL":      resolverResponseErrors,
		"FORMERR":       resolverResponseErrors,
		"OtherError":    resolverResponseErrors,
		"ValOk":         resolverDNSSECSucess,
		"ValNegOk":      resolverDNSSECSucess,
	}
	serverQueryErrors = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "query_errors_total"),
		"Number of query failures.",
		[]string{"error"}, nil,
	)
	serverReponses = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "responses_total"),
		"Number of responses sent.",
		[]string{"result"}, nil,
	)
	serverLabelStats = map[string]*prometheus.Desc{
		"QryDuplicate": serverQueryErrors,
		"QryDropped":   serverQueryErrors,
		"QryFailure":   serverQueryErrors,
		"QrySuccess":   serverReponses,
		"QryReferral":  serverReponses,
		"QryNxrrset":   serverReponses,
		"QrySERVFAIL":  serverReponses,
		"QryFORMERR":   serverReponses,
		"QryNXDOMAIN":  serverReponses,
	}
	tasksRunning = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "tasks_running"),
		"Number of running tasks.",
		nil, nil,
	)
	workerThreads = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "worker_threads"),
		"Total number of available worker threads.",
		nil, nil,
	)
)

// Exporter collects Binds stats from the given server and exports
// them using the prometheus metrics package.
type Exporter struct {
	URI     string
	metrics []string
	version string
	client  *http.Client
}

// NewExporter returns an initialized Exporter.
func NewExporter(URI string, metrics []string, timeout time.Duration) *Exporter {
	return &Exporter{
		URI:     URI,
		metrics: metrics,
		client: &http.Client{
			Transport: &http.Transport{
				Dial: func(netw, addr string) (net.Conn, error) {
					c, err := net.DialTimeout(netw, addr, timeout)
					if err != nil {
						return nil, err
					}
					if err := c.SetDeadline(time.Now().Add(timeout)); err != nil {
						return nil, err
					}
					return c, nil
				},
			},
		},
	}
}

func (e *Exporter) GetV3URI(metric string) string {
	if e.URI[len(e.URI)-1] == byte('/') {
		return e.URI + "xml/v3/" + metric
	} else {
		return e.URI + "/xml/v3/" + metric
	}
}

func (e *Exporter) GetVersion() (string, error) {
	// cached, use that
	if e.version != "" {
		return e.version, nil
	}

	resp, err := e.client.Get(e.GetV3URI("status"))
	if err != nil {
		log.Error("Error while querying Bind: ", err)
		return "", err
	}

	defer resp.Body.Close()

	if resp.StatusCode >= 500 {
		// 5xx is for server errors, abort search
		log.Error("Error while querying Bind: ", resp.Status)
		return "", errors.New(resp.Status)
	}
	if resp.StatusCode < 300 && resp.StatusCode >= 200 {
		return "v3", nil
	}

	return "v2", nil
}

// Describe describes all the metrics ever exported by the bind
// exporter. It implements prometheus.Collector.
func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {
	ch <- up
	ch <- incomingQueries
	ch <- incomingRequests
	ch <- resolverDNSSECSucess
	ch <- resolverQueries
	ch <- resolverQueryDuration
	ch <- resolverQueryErrors
	ch <- resolverResponseErrors
	for _, desc := range resolverMetricStats {
		ch <- desc
	}
	ch <- serverReponses
	ch <- tasksRunning
	ch <- workerThreads
}

func (e *Exporter) Fetch(uri string) ([]byte, error) {
	resp, err := e.client.Get(uri)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return body, nil
}

func (e *Exporter) FetchV2() (*BindRootV2, error) {
	data, err := e.Fetch(e.URI)
	if err != nil {
		return nil, err
	}

	root := BindRootV2{}
	if err := xml.Unmarshal(data, &root); err != nil {
		return nil, err
	}

	return &root, nil
}

func (e *Exporter) FetchV3() (*BindRootV3, error) {
	root := BindRootV3{}

	for _, metric := range e.metrics {
		body, err := e.Fetch(e.GetV3URI(metric))
		if err != nil {
			return nil, err
		}

		if err := xml.Unmarshal(body, &root); err != nil {
			return nil, err
		}
	}

	root.dedup()

	return &root, nil
}

func (e *Exporter) UpdateV2(ch chan<- prometheus.Metric, root BindRootV2) {
	stats := root.Bind.Statistics
	for _, s := range stats.Server.QueriesIn.Rdtype {
		ch <- prometheus.MustNewConstMetric(
			incomingQueries, prometheus.CounterValue, float64(s.Counter), s.Name,
		)
	}
	for _, s := range stats.Server.Requests.Opcode {
		ch <- prometheus.MustNewConstMetric(
			incomingRequests, prometheus.CounterValue, float64(s.Counter), s.Name,
		)
	}

	for _, s := range stats.Server.NsStats {
		if desc, ok := serverLabelStats[s.Name]; ok {
			r := strings.TrimPrefix(s.Name, "Qry")
			ch <- prometheus.MustNewConstMetric(
				desc, prometheus.CounterValue, float64(s.Counter), r,
			)
		}
	}

	for _, v := range stats.Views {
		for _, s := range v.Cache {
			ch <- prometheus.MustNewConstMetric(
				resolverCache, prometheus.GaugeValue, float64(s.Counter), v.Name, s.Name,
			)
		}

		for _, s := range v.Rdtype {
			ch <- prometheus.MustNewConstMetric(
				resolverQueries, prometheus.CounterValue, float64(s.Counter), v.Name, s.Name,
			)
		}

		for _, s := range v.Resstat {
			if desc, ok := resolverMetricStats[s.Name]; ok {
				ch <- prometheus.MustNewConstMetric(
					desc, prometheus.CounterValue, float64(s.Counter), v.Name,
				)
			}
			if desc, ok := resolverLabelStats[s.Name]; ok {
				ch <- prometheus.MustNewConstMetric(
					desc, prometheus.CounterValue, float64(s.Counter), v.Name, s.Name,
				)
			}
		}

		if buckets, count, err := histogramV2(v.Resstat); err == nil {
			ch <- prometheus.MustNewConstHistogram(
				resolverQueryDuration, count, math.NaN(), buckets, v.Name,
			)
		} else {
			log.Warn("Error parsing RTT:", err)
		}
	}
	threadModel := stats.Taskmgr.ThreadModel
	ch <- prometheus.MustNewConstMetric(
		tasksRunning, prometheus.GaugeValue, float64(threadModel.TasksRunning),
	)
	ch <- prometheus.MustNewConstMetric(
		workerThreads, prometheus.GaugeValue, float64(threadModel.WorkerThreads),
	)
}

func (e *Exporter) UpdateV3(ch chan<- prometheus.Metric, root BindRootV3) {
	for _, counters := range root.Server.Counters {
		if counters.Type == "qtype" {
			for _, c := range counters.Counter {
				ch <- prometheus.MustNewConstMetric(
					incomingQueries, prometheus.CounterValue, float64(c.Counter), c.Name,
				)

			}
			continue
		}
		if counters.Type == "opcode" {
			for _, c := range counters.Counter {
				ch <- prometheus.MustNewConstMetric(
					incomingRequests, prometheus.CounterValue, float64(c.Counter), c.Name,
				)

			}
			continue
		}
		if counters.Type == "nsstat" {
			for _, c := range counters.Counter {
				if desc, ok := serverLabelStats[c.Name]; ok {
					r := strings.TrimPrefix(c.Name, "Qry")
					ch <- prometheus.MustNewConstMetric(
						desc, prometheus.CounterValue, float64(c.Counter), r,
					)
				}
			}
		}
	}

	for _, v := range root.Views {
		for _, c := range v.Cache {
			ch <- prometheus.MustNewConstMetric(
				resolverCache, prometheus.GaugeValue, float64(c.Counter), v.Name, c.Name,
			)
		}

		for _, c := range v.Counters {
			if c.Type == "resqtype" {
				counters := c.Counter
				for _, c := range counters {
					ch <- prometheus.MustNewConstMetric(
						resolverQueries, prometheus.CounterValue, float64(c.Counter), v.Name, c.Name,
					)
				}
			}
			if c.Type == "resstats" {
				counters := c.Counter
				for _, c := range counters {
					if desc, ok := resolverMetricStats[c.Name]; ok {
						ch <- prometheus.MustNewConstMetric(
							desc, prometheus.CounterValue, float64(c.Counter), v.Name,
						)
					}
					if desc, ok := resolverLabelStats[c.Name]; ok {
						ch <- prometheus.MustNewConstMetric(
							desc, prometheus.CounterValue, float64(c.Counter), v.Name, c.Name,
						)
					}
				}
				if buckets, count, err := histogramV3(counters); err == nil {
					ch <- prometheus.MustNewConstHistogram(
						resolverQueryDuration, count, math.NaN(), buckets, v.Name,
					)
				} else {
					log.Warn("Error parsing RTT:", err)
				}
			}
		}
	}
	threadModel := root.Taskmgr.ThreadModel
	ch <- prometheus.MustNewConstMetric(
		tasksRunning, prometheus.GaugeValue, float64(threadModel.TasksRunning),
	)
	ch <- prometheus.MustNewConstMetric(
		workerThreads, prometheus.GaugeValue, float64(threadModel.WorkerThreads),
	)
}

// Collect fetches the stats from configured bind location and
// delivers them as Prometheus metrics. It implements prometheus.Collector.
func (e *Exporter) Collect(ch chan<- prometheus.Metric) {
	var status float64
	defer func() {
		ch <- prometheus.MustNewConstMetric(up, prometheus.GaugeValue, status)
	}()

	version, err := e.GetVersion()

	if err != nil {
		// could not fetch metrics / determin the status of bind
		return
	}

	if version == "v3" {
		root, err := e.FetchV3()
		if err != nil {
			log.Error("Failed to fetch/unmarshal XML (v3): ", err)
			return
		}
		status = 1
		e.UpdateV3(ch, *root)
		return
	}

	root, err := e.FetchV2()
	if err != nil {
		log.Error("Failed to fetch/unmarshal XML (v3): ", err)
		return
	}
	status = 1
	e.UpdateV2(ch, *root)
	return

}

func histogramV2(stats []StatV2) (map[float64]uint64, uint64, error) {
	buckets := map[float64]uint64{}
	var count uint64

	for _, s := range stats {
		if strings.HasPrefix(s.Name, qryRTT) {
			b := math.Inf(0)
			if !strings.HasSuffix(s.Name, "+") {
				var err error
				rrt := strings.TrimPrefix(s.Name, qryRTT)
				b, err = strconv.ParseFloat(rrt, 32)
				if err != nil {
					return buckets, 0, fmt.Errorf("could not parse RTT: %s", rrt)
				}
			}

			buckets[b/1000] = count + uint64(s.Counter)
			count += uint64(s.Counter)
		}
	}
	return buckets, count, nil
}

func histogramV3(counters []CounterV3) (map[float64]uint64, uint64, error) {
	var err error
	buckets := map[float64]uint64{}

	for _, s := range counters {
		if strings.HasPrefix(s.Name, qryRTT) {
			b := math.Inf(0)
			if !strings.HasSuffix(s.Name, "+") {
				rrt := strings.TrimPrefix(s.Name, qryRTT)
				b, err = strconv.ParseFloat(rrt, 32)
				if err != nil {
					return buckets, 0, fmt.Errorf("could not parse RTT: %s", rrt)
				}
			}

			buckets[b/1000] = uint64(s.Counter)
		}
	}

	keys := make([]float64, len(buckets))
	i := 0
	for k, _ := range buckets {
		keys[i] = k
		i++
	}

	sort.Float64s(keys)
	count := uint64(0)
	for _, k := range keys {
		count = count + buckets[k]
		buckets[k] = count
	}

	return buckets, count, nil
}

func main() {
	var (
		listenAddress = flag.String("web.listen-address", ":9119", "Address to listen on for web interface and telemetry.")
		metricsPath   = flag.String("web.telemetry-path", "/metrics", "Path under which to expose metrics.")
		subMetrics    = flag.String("bind.metrics", "mem,server,net,zones", "Subset of metrics to fetch (bind 9.10 / v3 only) (available: status, mem, server, zones, tasks)")
		bindURI       = flag.String("bind.statsuri", "http://localhost:8053/", "HTTP XML API address of an Bind server.")
		bindTimeout   = flag.Duration("bind.timeout", 10*time.Second, "Timeout for trying to get stats from Bind.")
		bindPidFile   = flag.String("bind.pid-file", "", "Path to Bind's pid file to export process information.")
	)
	flag.Parse()

	prometheus.MustRegister(NewExporter(*bindURI, strings.Split(*subMetrics, ","), *bindTimeout))
	if *bindPidFile != "" {
		procExporter := prometheus.NewProcessCollectorPIDFn(
			func() (int, error) {
				content, err := ioutil.ReadFile(*bindPidFile)
				if err != nil {
					return 0, fmt.Errorf("Can't read pid file: %s", err)
				}
				value, err := strconv.Atoi(strings.TrimSpace(string(content)))
				if err != nil {
					return 0, fmt.Errorf("Can't parse pid file: %s", err)
				}
				return value, nil
			}, namespace)
		prometheus.MustRegister(procExporter)
	}

	log.Info("Starting Server: ", *listenAddress)
	http.Handle(*metricsPath, prometheus.Handler())
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>
             <head><title>Bind Exporter</title></head>
             <body>
             <h1>Bind Exporter</h1>
             <p><a href='` + *metricsPath + `'>Metrics</a></p>
             </body>
             </html>`))
	})
	log.Fatal(http.ListenAndServe(*listenAddress, nil))
}
