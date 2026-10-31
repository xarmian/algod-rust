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
	if out.Endpoints[2].Non2xx != out.Endpoints[2].Requests || out.Endpoints[2].Requests == 0 {
		t.Errorf("404 endpoint must count every request as non-2xx: %+v", out.Endpoints[2])
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
