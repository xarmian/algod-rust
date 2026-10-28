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

package micro

import (
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/committee"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/msgp/msgp"
)

// selector mirrors go-algorand's unexported agreement.selector
// (agreement/selector.go), the committee.Selector agreement passes to
// UnauthenticatedCredential.Verify. It is ported here because the agreement
// type is unexported. marshal is a copy of agreement/msgp_gen.go's
// (*selector).MarshalMsg, so ToBeHashed costs and produces exactly what the
// real selector does: "AS" || canonical msgpack {per, rnd, seed, step}.
type selector struct {
	Seed   committee.Seed
	Round  basics.Round
	Period uint64
	Step   uint64
}

func (z *selector) marshal(b []byte) (o []byte) {
	o = msgp.Require(b, 4+1+msgp.Uint64Size+4+z.Round.Msgsize()+5+z.Seed.Msgsize()+5+msgp.Uint64Size)
	// map header, size 4; string "per"
	o = append(o, 0x84, 0xa3, 0x70, 0x65, 0x72)
	o = msgp.AppendUint64(o, z.Period)
	// string "rnd"
	o = append(o, 0xa3, 0x72, 0x6e, 0x64)
	o = z.Round.MarshalMsg(o)
	// string "seed"
	o = append(o, 0xa4, 0x73, 0x65, 0x65, 0x64)
	o = z.Seed.MarshalMsg(o)
	// string "step"
	o = append(o, 0xa4, 0x73, 0x74, 0x65, 0x70)
	o = msgp.AppendUint64(o, z.Step)
	return
}

// ToBeHashed implements crypto.Hashable (agreement/selector.go).
func (z selector) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.AgreementSelector, z.marshal(nil)
}

// CommitteeSize mirrors agreement's step.committeeSize (agreement/types.go).
func (z selector) CommitteeSize(proto config.ConsensusParams) uint64 {
	switch z.Step {
	case 0:
		return proto.NumProposers
	case 1:
		return proto.SoftCommitteeSize
	case 2:
		return proto.CertCommitteeSize
	case 253:
		return proto.LateCommitteeSize
	case 254:
		return proto.RedoCommitteeSize
	case 255:
		return proto.DownCommitteeSize
	default:
		return proto.NextCommitteeSize
	}
}
