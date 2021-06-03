// Copyright 2020 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package bind

import (
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"time"
)

// Client queries the BIND API, parses the response and returns stats in a
// generic format.
type Client interface {
	Stats(...StatisticGroup) (Statistics, error)
}

// XMLClient is a generic BIND API client to retrieve statistics in XML format.
type XMLClient struct {
	url  string
	http *http.Client
}

// NewXMLClient returns an initialized XMLClient.
func NewXMLClient(url string, c *http.Client) *XMLClient {
	return &XMLClient{
		url:  url,
		http: c,
	}
}

// Get queries the given path and stores the result in the value pointed to by
// v. The endpoint must return a valid XML representation which can be
// unmarshaled into the provided value.
func (c *XMLClient) Get(p string, v interface{}) error {
	u, err := url.Parse(c.url)
	if err != nil {
		return fmt.Errorf("invalid URL %q: %s", c.url, err)
	}
	u.Path = path.Join(u.Path, p)

	resp, err := c.http.Get(u.String())
	if err != nil {
		return fmt.Errorf("error querying stats: %s", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %s", resp.Status)
	}

	dec := xml.NewDecoder(resp.Body)
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("failed to unmarshal XML response: %s", err)
	}

	return nil
}

const (
	// QryRTT is the common prefix of query round-trip histogram counters.
	QryRTT = "QryRTT"
)

// StatisticGroup describes a sub-group of BIND statistics.
type StatisticGroup string

// Available statistic groups.
const (
	ServerStats StatisticGroup = "server"
	ViewStats   StatisticGroup = "view"
	TaskStats   StatisticGroup = "tasks"
)

// Statistics is a generic representation of BIND statistics.
type Statistics struct {
	Server      Server
	Views       []View
	ZoneViews   []ZoneView
	TaskManager TaskManager
}

// Server represents BIND server statistics.
type Server struct {
	BootTime         time.Time
	ConfigTime       time.Time
	IncomingQueries  []Counter
	IncomingRequests []Counter
	NameServerStats  []Counter
	ZoneStatistics   []Counter
}

// View represents statistics for a single BIND view.
type View struct {
	Name            string
	Cache           []Gauge
	ResolverStats   []Counter
	ResolverQueries []Counter
}

// View represents statistics for a single BIND zone view.
type ZoneView struct {
	Name     string
	ZoneData []ZoneCounter
}

// TaskManager contains information about all running tasks.
type TaskManager struct {
	Tasks       []Task      `xml:"tasks>task"`
	ThreadModel ThreadModel `xml:"thread-model"`
}

// Counter represents a single counter value.
type Counter struct {
	Name    string `xml:"name,attr"`
	Counter uint64 `xml:",chardata"`
}

// Counter represents a single zone counter value.
type ZoneCounter struct {
	Name   string
	Serial string
}

// Gauge represents a single gauge value.
type Gauge struct {
	Name  string `xml:"name"`
	Gauge uint64 `xml:"counter"`
}

// Task represents a single running task.
type Task struct {
	ID         string `xml:"id"`
	Name       string `xml:"name"`
	Quantum    uint64 `xml:"quantum"`
	References uint64 `xml:"references"`
	State      string `xml:"state"`
}

// ThreadModel contains task and worker information.
type ThreadModel struct {
	Type           string `xml:"type"`
	WorkerThreads  uint64 `xml:"worker-threads"`
	DefaultQuantum uint64 `xml:"default-quantum"`
	TasksRunning   uint64 `xml:"tasks-running"`
}
