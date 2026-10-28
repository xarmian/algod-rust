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

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
)

// algodClient is a minimal REST client for the node the generator drives.
// It uses the admin token, which every route accepts.
type algodClient struct {
	base  string
	token string
	http  *http.Client
}

func newClientFromDataDir(dir string) (*algodClient, error) {
	netb, err := os.ReadFile(filepath.Join(dir, "algod.net"))
	if err != nil {
		return nil, err
	}
	tok, err := os.ReadFile(filepath.Join(dir, "algod.admin.token"))
	if err != nil {
		return nil, err
	}
	return &algodClient{
		base:  "http://" + strings.TrimSpace(string(netb)),
		token: strings.TrimSpace(string(tok)),
		http:  &http.Client{Timeout: 60 * time.Second},
	}, nil
}

func (c *algodClient) do(method, path string, body []byte) (int, []byte, error) {
	req, err := http.NewRequest(method, c.base+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("X-Algo-API-Token", c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/x-binary")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return resp.StatusCode, b, err
}

func (c *algodClient) getJSON(path string, out interface{}) error {
	code, b, err := c.do(http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	if code != http.StatusOK {
		return fmt.Errorf("GET %s: HTTP %d: %s", path, code, b)
	}
	return json.Unmarshal(b, out)
}

// waitReady polls /v2/status until the node answers.
func (c *algodClient) waitReady(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		var st struct {
			LastRound uint64 `json:"last-round"`
		}
		err := c.getJSON("/v2/status", &st)
		if err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("node not ready after %v: %w", timeout, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (c *algodClient) lastRound() (uint64, error) {
	var st struct {
		LastRound uint64 `json:"last-round"`
	}
	err := c.getJSON("/v2/status", &st)
	return st.LastRound, err
}

func (c *algodClient) setTimestampOffset(sec uint64) error {
	code, b, err := c.do(http.MethodPost, fmt.Sprintf("/v2/devmode/blocks/offset/%d", sec), nil)
	if err != nil {
		return err
	}
	if code != http.StatusOK {
		return fmt.Errorf("set devmode timestamp offset: HTTP %d: %s", code, b)
	}
	return nil
}

func encodeGroup(group []transactions.SignedTxn) []byte {
	var enc []byte
	for i := range group {
		enc = append(enc, protocol.Encode(&group[i])...)
	}
	return enc
}

// submitSync posts a group to /v2/transactions. In DevMode this assembles
// and commits the next block (from everything in the pool) before replying.
func (c *algodClient) submitSync(group []transactions.SignedTxn) error {
	code, b, err := c.do(http.MethodPost, "/v2/transactions", encodeGroup(group))
	if err != nil {
		return err
	}
	if code != http.StatusOK {
		return fmt.Errorf("POST /v2/transactions: HTTP %d: %s", code, b)
	}
	return nil
}

// submitAsync posts a group to /v2/transactions/async, which only adds it to
// the pool (no block in DevMode), then waits until the pool holds `want`
// transactions. Waiting for each group before sending the next keeps the
// pool (and so the block payset) in exactly the planned order: the async
// path verifies groups concurrently and could otherwise reorder them.
func (c *algodClient) submitAsync(group []transactions.SignedTxn, want int) error {
	code, b, err := c.do(http.MethodPost, "/v2/transactions/async", encodeGroup(group))
	if err != nil {
		return err
	}
	if code != http.StatusOK {
		return fmt.Errorf("POST /v2/transactions/async: HTTP %d: %s", code, b)
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		var p struct {
			Total int `json:"total-transactions"`
		}
		if err := c.getJSON("/v2/transactions/pending?max=1", &p); err != nil {
			return err
		}
		if p.Total == want {
			return nil
		}
		if p.Total > want {
			return fmt.Errorf("pool holds %d txns, expected %d (unplanned transaction in the pool)", p.Total, want)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("async group not in the pool after 30s (pool %d, want %d): rejected by verification? see node.log", p.Total, want)
		}
		time.Sleep(200 * time.Microsecond)
	}
}

// rawBlock returns the exact /v2/blocks/{r}?format=msgpack response body
// (msgpack map {"block": ..., "cert": ...}).
func (c *algodClient) rawBlock(r uint64) ([]byte, error) {
	var last error
	for i := 0; i < 50; i++ {
		code, b, err := c.do(http.MethodGet, fmt.Sprintf("/v2/blocks/%d?format=msgpack", r), nil)
		if err == nil && code == http.StatusOK {
			return b, nil
		}
		if err != nil {
			last = err
		} else {
			last = fmt.Errorf("GET /v2/blocks/%d: HTTP %d: %s", r, code, b)
		}
		time.Sleep(20 * time.Millisecond)
	}
	return nil, last
}

func (c *algodClient) accountAmount(addr string) (uint64, error) {
	var a struct {
		Amount uint64 `json:"amount"`
	}
	err := c.getJSON("/v2/accounts/"+addr+"?exclude=all", &a)
	return a.Amount, err
}

type supply struct {
	Round       uint64 `json:"current_round"`
	OnlineMoney uint64 `json:"online-money"`
	TotalMoney  uint64 `json:"total-money"`
}

func (c *algodClient) supply() (supply, error) {
	var s supply
	err := c.getJSON("/v2/ledger/supply", &s)
	return s, err
}
