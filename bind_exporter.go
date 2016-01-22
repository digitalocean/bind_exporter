package main

import (
	"encoding/xml"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	_ "net/http/pprof"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/log"
)

const (
	namespace = "bind"
)

var (
	up = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "up"),
		"Was the Bind instance query successful?",
		nil, nil,
	)
	incomingQueries = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "incoming_queries_total"),
		"Number of incomming DNS queries.",
		[]string{"name"}, nil,
	)
	incomingRequests = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "incoming_requests_total"),
		"Number of incomming DNS queries.",
		[]string{"name"}, nil,
	)
)

// Exporter collects Binds stats from the given server and exports
// them using the prometheus metrics package.
type Exporter struct {
	URI    string
	client *http.Client
}

// NewExporter returns an initialized Exporter.
func NewExporter(uri string, timeout time.Duration) *Exporter {
	return &Exporter{
		URI: uri,
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

// Describe describes all the metrics ever exported by the bind
// exporter. It implements prometheus.Collector.
func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {
	ch <- up
	ch <- incomingQueries
	ch <- incomingRequests
}

// Collect fetches the stats from configured bind location and
// delivers them as Prometheus metrics. It implements prometheus.Collector.
func (e *Exporter) Collect(ch chan<- prometheus.Metric) {
	var status float64
	defer func() {
		ch <- prometheus.MustNewConstMetric(up, prometheus.GaugeValue, status)
	}()

	resp, err := e.client.Get(e.URI)
	if err != nil {
		log.Error("Error while querying Bind: ", err)
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Error("Failed to read XML response body: ", err)
		return
	}

	status = 1

	root := Isc{}
	if err := xml.Unmarshal([]byte(body), &root); err != nil {
		log.Error("Failed to unmarshal XML response: ", err)
		return
	}

	serverNode := root.Bind.Statistics.Server
	for _, s := range serverNode.QueriesIn.Rdtype {
		ch <- prometheus.MustNewConstMetric(
			incomingQueries, prometheus.CounterValue, float64(s.Counter), s.Name,
		)
	}
	for _, s := range serverNode.Requests.Opcode {
		ch <- prometheus.MustNewConstMetric(
			incomingRequests, prometheus.CounterValue, float64(s.Counter), s.Name,
		)
	}
}

func main() {
	var (
		listenAddress = flag.String("web.listen-address", ":9109", "Address to listen on for web interface and telemetry.")
		metricsPath   = flag.String("web.telemetry-path", "/metrics", "Path under which to expose metrics.")
		bindURI       = flag.String("bind.statsuri", "http://localhost:8053/", "HTTP XML API address of an Bind server.")
		bindTimeout   = flag.Duration("bind.timeout", 10*time.Second, "Timeout for trying to get stats from Bind.")
		bindPidFile   = flag.String("bind.pid-file", "", "Path to Bind's pid file to export process information.")
	)
	flag.Parse()

	prometheus.MustRegister(NewExporter(*bindURI, *bindTimeout))
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
