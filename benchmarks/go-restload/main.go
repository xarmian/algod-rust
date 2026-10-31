// Copyright (c) 2026 Algod DAO
// SPDX-License-Identifier: MIT
// See the LICENSE-MIT file in the repository root for the full license text.

// Command restload is the one HTTP load generator of the bench-compare `rest`
// tier (issue #2107, epic #2101). It sends the same fixed request set to a
// node at a fixed concurrency and reports, per endpoint, requests per second
// and the p50/p95/p99 latency. The same binary drives go-algorand's algod and
// algod-rust, so the client cost is identical on both sides.
//
//	restload -base http://127.0.0.1:4300 -token T -requests reqs.json \
//	         -concurrency 16 -duration 5s -warmup 1s -out result.json
//
// reqs.json is a JSON array of {name, method, path, content_type, body_b64,
// accept}. Each endpoint is loaded on its own (one after the other), so a
// slow endpoint cannot hide behind a fast one.
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

type request struct {
	Name        string `json:"name"`
	Method      string `json:"method"`
	Path        string `json:"path"`
	ContentType string `json:"content_type"`
	Accept      string `json:"accept"`
	BodyB64     string `json:"body_b64"`
	body        []byte
}

type endpointResult struct {
	Name      string  `json:"name"`
	Requests  int64   `json:"requests"` // attempted
	OK        int64   `json:"ok"`       // answered 2xx: the only ones in rps and the percentiles
	Errors    int64   `json:"errors"`
	Non2xx    int64   `json:"non_2xx"`
	DurationS float64 `json:"duration_s"`
	RPS       float64 `json:"rps"`
	P50Ms     float64 `json:"p50_ms"`
	P95Ms     float64 `json:"p95_ms"`
	P99Ms     float64 `json:"p99_ms"`
	MaxMs     float64 `json:"max_ms"`
	Bytes     int64   `json:"bytes"`
}

type output struct {
	Schema      string           `json:"schema"`
	Base        string           `json:"base"`
	Concurrency int              `json:"concurrency"`
	DurationS   float64          `json:"duration_s"`
	WarmupS     float64          `json:"warmup_s"`
	Endpoints   []endpointResult `json:"endpoints"`
}

// percentile of an ascending-sorted sample, nearest-rank: the smallest value
// with at least p% of the sample at or below it.
func percentile(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	rank := int(p/100*float64(len(sorted)) + 0.999999999)
	if rank < 1 {
		rank = 1
	}
	if rank > len(sorted) {
		rank = len(sorted)
	}
	return sorted[rank-1]
}

func ms(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }

// summarize reports an endpoint. `lat` holds the latencies of the SUCCESSFUL
// requests only: a failed request (transport error, non-2xx) is usually fast
// or slow for reasons unrelated to serving, so it must not enter req/s or the
// percentiles. Failures are reported separately (errors, non_2xx) and the
// caller derives the error rate.
func summarize(name string, lat []time.Duration, errs, non2xx, bytesRead int64, dur time.Duration) endpointResult {
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	r := endpointResult{Name: name, Requests: int64(len(lat)) + errs + non2xx, OK: int64(len(lat)),
		Errors: errs, Non2xx: non2xx, DurationS: dur.Seconds(), Bytes: bytesRead}
	if dur > 0 {
		r.RPS = float64(len(lat)) / dur.Seconds()
	}
	r.P50Ms = ms(percentile(lat, 50))
	r.P95Ms = ms(percentile(lat, 95))
	r.P99Ms = ms(percentile(lat, 99))
	if len(lat) > 0 {
		r.MaxMs = ms(lat[len(lat)-1])
	}
	return r
}

func newClient(conc int) *http.Client {
	tr := &http.Transport{
		MaxIdleConns:        conc,
		MaxIdleConnsPerHost: conc,
		MaxConnsPerHost:     conc,
		DisableCompression:  true, // the same bytes on the wire for both nodes
		IdleConnTimeout:     time.Minute,
	}
	return &http.Client{Transport: tr, Timeout: 30 * time.Second}
}

func do(c *http.Client, base, token string, rq *request) (int, int64, error) {
	var body io.Reader
	if len(rq.body) > 0 {
		body = bytes.NewReader(rq.body)
	}
	req, err := http.NewRequest(rq.Method, base+rq.Path, body)
	if err != nil {
		return 0, 0, err
	}
	req.Header.Set("X-Algo-API-Token", token)
	if rq.ContentType != "" {
		req.Header.Set("Content-Type", rq.ContentType)
	}
	if rq.Accept != "" {
		req.Header.Set("Accept", rq.Accept)
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, 0, err
	}
	n, err := io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode, n, err
}

// load runs rq with `conc` closed-loop workers for `dur` and returns every
// successful request's latency. A transport error or a non-2xx answer is only
// counted.
func load(c *http.Client, base, token string, rq *request, conc int, dur time.Duration) (lat []time.Duration, errs, non2xx, nbytes int64, wall time.Duration) {
	var mu sync.Mutex
	var wg sync.WaitGroup
	var e, n2, nb atomic.Int64
	deadline := time.Now().Add(dur)
	start := time.Now()
	for w := 0; w < conc; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			local := make([]time.Duration, 0, 4096)
			for time.Now().Before(deadline) {
				t0 := time.Now()
				code, n, err := do(c, base, token, rq)
				d := time.Since(t0)
				nb.Add(n)
				if err != nil {
					e.Add(1)
				} else if code < 200 || code > 299 {
					n2.Add(1)
				} else {
					local = append(local, d)
				}
			}
			mu.Lock()
			lat = append(lat, local...)
			mu.Unlock()
		}()
	}
	wg.Wait()
	return lat, e.Load(), n2.Load(), nb.Load(), time.Since(start)
}

func loadRequests(path string) ([]request, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rs []request
	if err := json.Unmarshal(raw, &rs); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if len(rs) == 0 {
		return nil, fmt.Errorf("%s: no requests", path)
	}
	seen := map[string]bool{}
	for i := range rs {
		r := &rs[i]
		if r.Name == "" || r.Path == "" || seen[r.Name] {
			return nil, fmt.Errorf("%s: request %d has an empty or duplicate name or an empty path", path, i)
		}
		seen[r.Name] = true
		if r.Method == "" {
			r.Method = "GET"
		}
		if r.BodyB64 != "" {
			if r.body, err = base64.StdEncoding.DecodeString(r.BodyB64); err != nil {
				return nil, fmt.Errorf("%s: body_b64: %w", r.Name, err)
			}
		}
	}
	return rs, nil
}

func run(base, token string, rs []request, conc int, dur, warmup time.Duration) output {
	c := newClient(conc)
	out := output{Schema: "bench-restload/v1", Base: base, Concurrency: conc,
		DurationS: dur.Seconds(), WarmupS: warmup.Seconds()}
	for i := range rs {
		rq := &rs[i]
		if warmup > 0 {
			load(c, base, token, rq, conc, warmup)
		}
		lat, e, n2, nb, wall := load(c, base, token, rq, conc, dur)
		out.Endpoints = append(out.Endpoints, summarize(rq.Name, lat, e, n2, nb, wall))
	}
	return out
}

func main() {
	base := flag.String("base", "", "node base URL, e.g. http://127.0.0.1:4300")
	token := flag.String("token", "", "API token")
	reqs := flag.String("requests", "", "request set (JSON)")
	conc := flag.Int("concurrency", 16, "closed-loop workers")
	dur := flag.Duration("duration", 5*time.Second, "measured duration per endpoint")
	warmup := flag.Duration("warmup", time.Second, "discarded warm-up per endpoint")
	outPath := flag.String("out", "", "result JSON file (default stdout)")
	flag.Parse()
	if *base == "" || *reqs == "" || *conc < 1 || *dur <= 0 {
		fmt.Fprintln(os.Stderr, "usage: restload -base URL -token T -requests FILE [-concurrency N] [-duration D] [-warmup D] [-out FILE]")
		os.Exit(2)
	}
	rs, err := loadRequests(*reqs)
	if err != nil {
		fmt.Fprintln(os.Stderr, "restload:", err)
		os.Exit(2)
	}
	res := run(*base, *token, rs, *conc, *dur, *warmup)
	b, _ := json.MarshalIndent(res, "", " ")
	b = append(b, '\n')
	if *outPath == "" {
		os.Stdout.Write(b)
		return
	}
	if err := os.WriteFile(*outPath, b, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "restload:", err)
		os.Exit(1)
	}
}
