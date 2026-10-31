// Copyright (c) 2026 Algod DAO
// SPDX-License-Identifier: MIT
// See the LICENSE-MIT file in the repository root for the full license text.

package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestPercentileNearestRank(t *testing.T) {
	var s []time.Duration
	for i := 1; i <= 100; i++ {
		s = append(s, time.Duration(i)*time.Millisecond)
	}
	for _, c := range []struct {
		p    float64
		want time.Duration
	}{{50, 50 * time.Millisecond}, {95, 95 * time.Millisecond}, {99, 99 * time.Millisecond}, {100, 100 * time.Millisecond}, {0, time.Millisecond}} {
		if got := percentile(s, c.p); got != c.want {
			t.Errorf("p%v = %v, want %v", c.p, got, c.want)
		}
	}
	if percentile(nil, 50) != 0 {
		t.Error("empty sample must give 0")
	}
	if got := percentile([]time.Duration{7 * time.Millisecond}, 99); got != 7*time.Millisecond {
		t.Errorf("single sample p99 = %v", got)
	}
}

func TestRunSendsTokenBodyAndCountsStatuses(t *testing.T) {
	var sawToken, sawBody atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Algo-API-Token") == "tok" {
			sawToken.Store(true)
		}
		if r.Method == "POST" && r.URL.Path == "/post" {
			b := make([]byte, 5)
			n, _ := r.Body.Read(b)
			if string(b[:n]) == "hello" {
				sawBody.Store(true)
			}
		}
		if r.URL.Path == "/missing" {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte("ok"))
	}))
	defer srv.Close()
	p := filepath.Join(t.TempDir(), "r.json")
	os.WriteFile(p, []byte(`[{"name":"get","path":"/x"},{"name":"post","method":"POST","path":"/post","body_b64":"aGVsbG8="},{"name":"nf","path":"/missing"}]`), 0o644)
	rs, err := loadRequests(p)
	if err != nil {
		t.Fatal(err)
	}
	out := run(srv.URL, "tok", rs, 2, 80*time.Millisecond, 0)
	if len(out.Endpoints) != 3 || !sawToken.Load() || !sawBody.Load() {
		t.Fatalf("endpoints=%d token=%v body=%v", len(out.Endpoints), sawToken.Load(), sawBody.Load())
	}
	if out.Endpoints[0].Requests == 0 || out.Endpoints[0].Errors != 0 || out.Endpoints[0].Non2xx != 0 {
		t.Errorf("get: %+v", out.Endpoints[0])
	}
	nf := out.Endpoints[2]
	if nf.Non2xx != nf.Requests || nf.Requests == 0 || nf.OK != 0 {
		t.Errorf("404 endpoint must count every request as non-2xx: %+v", nf)
	}
	// Failed requests are not throughput and not latency.
	if nf.RPS != 0 || nf.P50Ms != 0 || nf.P95Ms != 0 || nf.P99Ms != 0 || nf.MaxMs != 0 {
		t.Errorf("a 404 endpoint must report no rps / latency: %+v", nf)
	}
	if out.Endpoints[0].OK != out.Endpoints[0].Requests {
		t.Errorf("get: ok %d != requests %d", out.Endpoints[0].OK, out.Endpoints[0].Requests)
	}
}

func TestRunReportsTheMeasuredWindow(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer srv.Close()
	rs := []request{{Name: "w", Method: "GET", Path: "/"}}
	before := unixSeconds(time.Now())
	out := run(srv.URL, "t", rs, 1, 100*time.Millisecond, 100*time.Millisecond)
	after := unixSeconds(time.Now())
	e := out.Endpoints[0]
	// the warm-up precedes the window; the window is at least the duration long
	if e.StartUnix < before+0.09 || e.EndUnix > after || e.EndUnix-e.StartUnix < 0.1 {
		t.Fatalf("window [%v, %v] not inside [%v, %v] after a 0.1 s warm-up", e.StartUnix, e.EndUnix, before, after)
	}
}

func TestSummarizeUsesSuccessfulRequestsOnly(t *testing.T) {
	// 4 successes of 10..40 ms, 6 failures: rps counts 4, percentiles use 4.
	lat := []time.Duration{40 * time.Millisecond, 10 * time.Millisecond, 30 * time.Millisecond, 20 * time.Millisecond}
	r := summarize("x", lat, 2, 4, 100, 2*time.Second)
	if r.Requests != 10 || r.OK != 4 || r.Errors != 2 || r.Non2xx != 4 {
		t.Fatalf("counts: %+v", r)
	}
	if r.RPS != 2 {
		t.Errorf("rps = %v, want 2 (4 ok / 2 s)", r.RPS)
	}
	if r.P50Ms != 20 || r.MaxMs != 40 {
		t.Errorf("percentiles must come from the successes: %+v", r)
	}
}

func TestMixedEndpointCountsFailuresSeparately(t *testing.T) {
	var n atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1)%2 == 0 {
			http.Error(w, "boom", 500)
			return
		}
		w.Write([]byte("ok"))
	}))
	defer srv.Close()
	rs := []request{{Name: "m", Method: "GET", Path: "/"}}
	out := run(srv.URL, "t", rs, 2, 120*time.Millisecond, 0)
	e := out.Endpoints[0]
	if e.OK == 0 || e.Non2xx == 0 || e.Requests != e.OK+e.Non2xx+e.Errors {
		t.Fatalf("mixed: %+v", e)
	}
}

func TestLoadRequestsRejectsBadSets(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"empty":   `[]`,
		"dup":     `[{"name":"a","path":"/a"},{"name":"a","path":"/b"}]`,
		"nopath":  `[{"name":"a"}]`,
		"badbody": `[{"name":"a","path":"/a","body_b64":"!!"}]`,
	} {
		p := filepath.Join(dir, name+".json")
		os.WriteFile(p, []byte(body), 0o644)
		if _, err := loadRequests(p); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}
