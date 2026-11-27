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

// Parity oracle for algod-rust issue #2555 (go-algorand v5.1.0-beta #6808):
// the exact response bytes of go v5.1.1-stable's jsonSerializer
// (daemon/algod/api/server/json.go, encoding/json/v2 with DefaultOptionsV1)
// for an error message holding every kind of byte string, next to what
// echo's default serializer (encoding/json v1's Encoder) writes. It is staged
// into daemon/algod/api/server of a go-algorand checkout (package server, for
// the unexported serializer) and writes one JSON object per case to
// $ORACLE_OUT: the message as hex, the response body of each serializer as hex.
package server

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated/model"
)

type jsonSerializerCase struct {
	Name    string `json:"name"`
	Message string `json:"message_hex"`
	V2      string `json:"v2_hex"`
	Echo    string `json:"echo_hex"`
}

func oracleSerialize(s echo.JSONSerializer, v any) string {
	rec := httptest.NewRecorder()
	c := echo.New().NewContext(httptest.NewRequest(http.MethodGet, "/", nil), rec)
	if err := s.Serialize(c, v, ""); err != nil {
		return "error: " + err.Error()
	}
	return hex.EncodeToString(rec.Body.Bytes())
}

func TestAlgodRustJSONSerializerOracle(t *testing.T) {
	messages := map[string]string{
		"ascii":               "plain",
		"html":                "<b>&</b>",
		"separators":          "a b c",
		"controls":            "a\x00b\x01c\x1fd\x7fe\ta\nb\rc\"d\\e",
		"invalid lead":        "a\xffb",
		"invalid continuation": "a\x80b",
		"truncated 2":         "a\xc3",
		"truncated 3":         "a\xe2\x82 b",
		"truncated 4":         "a\xf0\x9f\x98",
		"surrogate":           "a\xed\xa0\x80b",
		"overlong":            "a\xc0\x80b",
		"above max":           "a\xf4\x90\x80\x80b",
		"valid replacement":   "a�b",
		"two invalid":         "\xff\xfe",
		"valid unicode":       "é€😀",
		"noncharacter":        "a￾b￿c",
		"invalid then html":   "\xff<\xfe>",
	}
	var out []byte
	for name, msg := range messages {
		resp := model.ErrorResponse{Message: msg}
		out = append(out, mustJSON(t, jsonSerializerCase{
			Name:    name,
			Message: hex.EncodeToString([]byte(msg)),
			V2:      oracleSerialize(jsonSerializer{}, resp),
			Echo:    oracleSerialize(echo.DefaultJSONSerializer{}, resp),
		})...)
		out = append(out, '\n')
	}
	require.NoError(t, os.WriteFile(os.Getenv("ORACLE_OUT"), out, 0o644))
}

func mustJSON(t *testing.T, v any) []byte {
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return b
}
