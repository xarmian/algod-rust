// Copyright (C) 2019-2026 Algorand Foundation Ltd.
// Modifications Copyright (C) 2026 Algod DAO
// This file is part of algod-rust, a modified work based on go-algorand
// (https://github.com/algorand/go-algorand).
//
// algod-rust is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// algod-rust is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with algod-rust.  If not, see <https://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Parity oracle for algod-rust issue #2556: how go-algorand v5.1.1-stable's
// kmd API (daemon/kmd/api.Handler, which moved from gorilla/mux to
// http.ServeMux) answers requests: status, the headers that matter and the
// body for every method x path x token x origin combination below, plus how
// often the watchdog callback ran. The Rust test
// crates/node/algo-kmd/src/server.rs (`kmd_routing_matches_go_on_every_oracle_row`)
// replays them through its router.
//
// The test is staged into daemon/kmd/api of a go-algorand checkout at the pin:
//
//	cp tools/kmd-route-oracle/oracle_test.go \
//	   ../go-algorand/daemon/kmd/api/zz_algod_rust_kmd_route_oracle_test.go
//	(cd ../go-algorand && ORACLE_OUT=$PWD/kmd_out.jsonl go test -count=1 \
//	   -run '^TestAlgodRustKmdRouteOracle$' ./daemon/kmd/api/)
//	cp ../go-algorand/kmd_out.jsonl \
//	   crates/node/algo-kmd/tests/fixtures/kmd_route_oracle.jsonl
package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/daemon/kmd/config"
	"github.com/algorand/go-algorand/daemon/kmd/session"
	"github.com/algorand/go-algorand/logging"
)

const oracleToken = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestAlgodRustKmdRouteOracle(t *testing.T) {
	outPath := os.Getenv("ORACLE_OUT")
	require.NotEmpty(t, outPath, "set ORACLE_OUT")
	f, err := os.Create(outPath)
	require.NoError(t, err)
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetEscapeHTML(false)

	paths := []string{
		"/", "/versions", "/versions/", "/swagger.json", "/swagger.json/", "/nonexistent", "/V1/wallets",
		"/v1", "/v1/", "/v1/wallets", "/v1/wallets/", "/v1/wallet", "/v1/wallet/", "/v1/wallet/info", "/v1/wallet/info/",
		"/v1/wallet/init", "/v1/wallet/release", "/v1/wallet/renew", "/v1/wallet/rename", "/v1/master-key/export",
		"/v1/key", "/v1/key/", "/v1/key/list", "/v1/key/import", "/v1/key/export",
		"/v1/multisig", "/v1/multisig/list", "/v1/multisig/sign", "/v1/multisig/signprogram", "/v1/multisig/import",
		"/v1/multisig/export", "/v1/transaction/sign", "/v1/program/sign", "/v1/nonexistent", "/v1/key/nonexistent",
		"//versions", "//", "/v1//wallets", "/v1//key/list", "/v1/./wallets", "/v1/key/../wallet/info", "/v1/../versions",
		"/./", "/..", "/v1/wallets/..", "/v1/wallets/.", "/%2e%2e/versions", "/v1/%2e%2e/versions", "/v1%2Fwallets",
		"/v1/wal%6cets", "/v1/key/%6cist", "/versions%20", "/v1/w%C3%A4llets", "/v1/wallets%00", "/v1/wallets?x=1",
		"/versions?x=1", "/v1/key/list?a=b&c=d", "//versions?x=1", "/nonexistent//", "/a%2Fb", "/v1/wallet%2Finfo",
		"/v1/wallets;x", "/v1/wallets%3Bx", "/v1/wallets%20",
	}
	methods := []string{"GET", "HEAD", "POST", "DELETE", "PUT", "PATCH", "OPTIONS", "TRACE"}
	tokens := []string{"none", "ok", "bad"}

	type setup struct {
		name    string
		origins []string
		pna     bool
		// reqOrigin is the Origin header sent ("" for none)
		reqOrigin string
	}
	setups := []setup{
		{"plain", nil, false, ""},
		{"localhost", []string{"http://localhost:3000"}, false, "http://localhost:3000"},
		{"localhost-evil", []string{"http://localhost:3000"}, false, "http://evil.com"},
		{"localhost-no-origin", []string{"http://localhost:3000"}, false, ""},
		{"wildcard-pna", []string{"*"}, true, "http://anything.example.com"},
		{"wildcard-no-origin", []string{"*"}, false, ""},
	}

	for _, su := range setups {
		for _, path := range paths {
			for _, method := range methods {
				for _, tok := range tokens {
					// the full matrix for the plain setup; the others only for a few
					// representative combinations (CORS/PNA do not look at the route)
					if su.name != "plain" && !(tok == "ok" || tok == "none") {
						continue
					}
					if su.name != "plain" && !(method == "GET" || method == "OPTIONS" || method == "POST") {
						continue
					}
					var cbCalls atomic.Int32
					cfg := config.KMDConfig{SessionLifetimeSecs: 60}
					sm := session.MakeManager(cfg)
					log := logging.TestingLog(t)
					h := Handler(sm, log, su.origins, oracleToken, su.pna, func() { cbCalls.Add(1) })

					body := ""
					if method == "POST" || method == "DELETE" || method == "PUT" || method == "PATCH" {
						body = "{bad json"
					}
					// GET/HEAD on /v1/wallets with a valid token would list the real
					// wallets of the machine: skipped (the go tests skip it as well).
					if tok == "ok" && (method == "GET" || method == "HEAD") && (path == "/v1/wallets" || path == "/v1/wal%6cets" || path == "/v1/wallets?x=1") {
						sm.Kill()
						continue
					}
					var req *http.Request
					func() {
						defer func() {
							if r := recover(); r != nil {
								req = nil
							}
						}()
						req = httptest.NewRequest(method, path, strings.NewReader(body))
					}()
					if req == nil {
						sm.Kill()
						continue
					}
					switch tok {
					case "ok":
						req.Header.Set("X-KMD-API-Token", oracleToken)
					case "bad":
						req.Header.Set("X-KMD-API-Token", strings.Repeat("b", 64))
					}
					origin := su.reqOrigin
					if origin != "" {
						req.Header.Set("Origin", origin)
					}
					// sent on every request: only a preflight with PNA enabled answers it
					req.Header.Set("Access-Control-Request-Private-Network", "true")
					rr := httptest.NewRecorder()
					h.ServeHTTP(rr, req)
					sm.Kill()

					headers := map[string]string{}
					for _, name := range []string{
						"Content-Type", "Location", "X-Content-Type-Options", "Allow",
						"Access-Control-Allow-Origin", "Access-Control-Allow-Headers", "Access-Control-Allow-Methods",
						"Access-Control-Allow-Private-Network",
					} {
						if v := rr.Header().Get(name); v != "" {
							headers[name] = v
						}
					}
					require.NoError(t, enc.Encode(map[string]any{
						"setup": su.name, "origins": su.origins, "pna": su.pna, "origin": origin,
						"method": method, "path": path, "token": tok, "body": body,
						"status": rr.Code, "headers": headers, "response": rr.Body.String(), "cb_calls": cbCalls.Load(),
					}))
				}
			}
		}
	}
}
