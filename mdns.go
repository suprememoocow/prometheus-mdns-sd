// Copyright 2016 The Prometheus Authors
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

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"hash/fnv"
	"log"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/common/model"

	"github.com/grandcat/zeroconf"
	"github.com/natefinch/atomic"
)

type TargetGroup struct {
	Targets []string          `json:"targets,omitempty"`
	Labels  map[string]string `json:"labels,omitempty"`
}

type TargetGroups []*TargetGroup

func (t TargetGroups) Len() int      { return len(t) }
func (t TargetGroups) Swap(i, j int) { t[i], t[j] = t[j], t[i] }
func (t TargetGroups) Less(i, j int) bool {
	ti := t[i]
	tj := t[j]

	// Dunno. Perhaps the other way around.
	if len(ti.Targets) == 0 {
		return false
	}
	if len(tj.Targets) == 0 {
		return true
	}

	return strings.Compare(ti.Targets[0], tj.Targets[0]) == -1
}

type arrayFlags []string

func (i *arrayFlags) String() string {
	return strings.Join(*i, ", ")
}

func (i *arrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

var (
	interval     = flag.Duration("interval", 10*time.Second, "How often to query for services")
	output       = flag.String("out", "-", "Filename to write output to")
	httpDomains  arrayFlags
	httpsDomains arrayFlags
)

func main() {
	flag.Var(&httpDomains, "http-domain", "Domain to use for mDNS discovery for http endpoints. Can be used multiple times.")
	flag.Var(&httpsDomains, "https-domain", "Domain to use for mDNS discovery for https endpoints. Can be used multiple times.")
	flag.Parse()

	// If no domains have been passed in via arguments, use the defaults
	if len(httpDomains) == 0 && len(httpsDomains) == 0 {
		httpDomains = append(httpDomains, "_prometheus-http._tcp")
		httpsDomains = append(httpDomains, "_prometheus-https._tcp")
	}

	d := &Discovery{
		interval: *interval,
	}

	ctx := context.Background()
	ch := make(chan []*TargetGroup)

	go d.Run(ctx, ch)

	var oldHash uint64 = 0

	func() {
		for targetList := range ch {
			targetGroups := TargetGroups(targetList)
			sort.Sort(&targetGroups)

			y, err := json.MarshalIndent(targetGroups, "", "\t")
			if err != nil {
				log.Fatal(err)
			}

			// Hash the output and skip writing if it isn't different from earlier
			hasher := fnv.New64()
			hasher.Write(y)
			newHash := hasher.Sum64()

			if newHash == oldHash {
				continue
			}
			oldHash = newHash

			if *output == "-" {
				fmt.Println(string(y))
			} else {
				buf := bytes.NewBuffer(y)
				if err := atomic.WriteFile(*output, buf); err != nil {
					log.Fatal(err)
				}
			}
		}
	}()
}

// Discovery periodically performs DNS-SD requests. It implements
// the TargetProvider interface.
type Discovery struct {
	interval time.Duration
}

// Run implements the TargetProvider interface.
func (dd *Discovery) Run(ctx context.Context, ch chan<- []*TargetGroup) {
	defer close(ch)

	ticker := time.NewTicker(dd.interval)
	defer ticker.Stop()

	// Get an initial set right away.
	dd.refreshAll(ctx, ch)

	for {
		select {
		case <-ticker.C:
			dd.refreshAll(ctx, ch)
		case <-ctx.Done():
			return
		}
	}
}

func (dd *Discovery) refreshAll(ctx context.Context, ch chan<- []*TargetGroup) {
	var wg sync.WaitGroup

	targetChan := make(chan *TargetGroup)
	targets := make([]*TargetGroup, 0)

	// Collect all lookup results into one list and emit it once they're all
	// done.
	go func() {
		for target := range targetChan {
			targets = append(targets, target)
		}

		ch <- targets
	}()

	wg.Add(len(httpDomains))
	for _, name := range httpDomains {
		go func(n string) {
			if err := dd.refresh(ctx, n, false, targetChan); err != nil {
				log.Printf("Error refreshing DNS targets: %s", err)
			}
			wg.Done()
		}(name)
	}

	wg.Add(len(httpsDomains))
	for _, name := range httpsDomains {
		go func(n string) {
			if err := dd.refresh(ctx, n, true, targetChan); err != nil {
				log.Printf("Error refreshing DNS targets: %s", err)
			}
			wg.Done()
		}(name)
	}

	// Close chan when all lookups are done
	wg.Wait()
	close(targetChan)
}

func (dd *Discovery) refresh(ctx context.Context, name string, isHTTPS bool, ch chan<- *TargetGroup) error {
	// Discover all services on the network (e.g. _workstation._tcp)
	resolver, err := zeroconf.NewResolver(nil)
	if err != nil {
		return fmt.Errorf("failed to create resolver: %w", err)
	}

	entries := make(chan *zeroconf.ServiceEntry)
	go func(results <-chan *zeroconf.ServiceEntry) {
		for response := range results {
			// Make a new targetGroup with one address-label for each thing we scape
			//
			// Check https://github.com/prometheus/common/blob/master/model/labels.go for possible labels.
			tg := &TargetGroup{
				Labels: map[string]string{
					model.InstanceLabel: strings.TrimRight(response.HostName, "."),
					model.SchemeLabel:   "http",
				},
				Targets: []string{},
			}

			// Set model.SchemeLabel to 'http' or 'https'
			if isHTTPS {
				tg.Labels[model.SchemeLabel] = "https"
			}

			// Parse InfoFields and set path as model.MetricsPathLabel if it's
			// there.
			for _, field := range response.Text {
				parts := strings.SplitN(field, "=", 2)

				// If there is no key, set one
				if len(parts) == 1 {
					parts = append(parts, "")
				}

				// Special-case query parameters too?
				if parts[0] == "path" {
					parts[0] = model.MetricsPathLabel
				} else {
					parts[0] = model.MetaLabelPrefix + /*"mdns_" +*/ parts[0]
				}

				tg.Labels[parts[0]] = parts[1]
			}

			// Figure out an address
			for _, v := range response.AddrIPv4 {
				ip, ok := netip.AddrFromSlice(v)
				if !ok {
					continue
				}
				ipPort := netip.AddrPortFrom(ip, uint16(response.Port))
				tg.Targets = append(tg.Targets, ipPort.String())
			}

			for _, v := range response.AddrIPv6 {
				ip, ok := netip.AddrFromSlice(v)
				if !ok {
					continue
				}
				ipPort := netip.AddrPortFrom(ip, uint16(response.Port))
				tg.Targets = append(tg.Targets, ipPort.String())
			}

			if len(tg.Targets) == 0 {
				continue
			}

			ch <- tg
		}
	}(entries)

	ctx, cancel := context.WithTimeout(ctx, time.Second*2)
	defer cancel()
	err = resolver.Browse(ctx, name, "local.", entries)
	if err != nil {
		return fmt.Errorf("failed to browse: %w", err)
	}

	<-ctx.Done()

	return nil
}
