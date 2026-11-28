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

// Command consensus-table-oracle is the whole-table ConsensusParams oracle of
// algod-rust issue #2543: it prints go-algorand v5.1.1-stable's complete
// `config.Consensus` table (every built-in protocol version, every field of
// `ConsensusParams`, as encoding/json prints it) so the Rust test
// crates/core/algo-types/tests/consensus_table_go_oracle_test.rs can compare
// every field of every version, and the set of field names, with
// algod-rust's built-in table.
//
// Build inside a go-algorand checkout (`make libsodium` first):
//
//	mkdir -p ../go-algorand/cmd/consensus-table-oracle
//	cp tools/consensus-table-oracle/main.go ../go-algorand/cmd/consensus-table-oracle/
//	(cd ../go-algorand && go run ./cmd/consensus-table-oracle) \
//	  > crates/core/algo-types/tests/fixtures/go_consensus_table.json
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/algorand/go-algorand/config"
)

func main() {
	enc, err := json.MarshalIndent(config.Consensus, "", " ")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(string(enc))
}
