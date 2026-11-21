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

// The goal cobra-tree oracle of algod-rust issue #2472: a test of go
// `goal`'s own package (`cmd/goal`, package main) that walks its cobra
// command tree and writes, for every command, what cobra v1.8.1 / pflag
// v1.0.6 parse a command line with: the command's name, aliases and
// whether it is hidden or runnable; its local and persistent flags (name,
// shorthand, pflag type, NoOptDefVal, MarkFlagRequired, hidden,
// deprecated); its `Args` rule, probed with 0 to 6 positional arguments;
// and its usage (`UsageString()`) and help (`HelpFunc()`) texts. It also
// writes the runes `strconv.IsPrint` rejects, which `%q` escapes.
//
// It is compiled into go-algorand's `cmd/goal` through `go test -overlay`,
// so the go-algorand checkout is not changed (its crypto package needs
// the vendored libsodium: `make libsodium` first):
//
//	printf '{"Replace":{"%s/cmd/goal/zz_cobra_dump_test.go":"%s"}}' \
//	  "$GOALGO" "$PWD/tools/goal-cobra-oracle/dump_test.go" > /tmp/overlay.json
//	(cd "$GOALGO" && GOAL_COBRA_DUMP_OUT=/tmp/cobra_tree.json \
//	  go test -overlay /tmp/overlay.json -run TestGoalCobraDump -count=1 ./cmd/goal)
//
// `crates/tools/goal-rust/tests/cobra_tree_e2e.rs` runs it
// (`MIXED_CLUSTER=1 REGEN_COBRA_TREE=1`) and writes the result to
// `crates/tools/goal-rust/src/cobra_tree.json`, the table goal-rust's
// `cobra_compat` parses command lines with.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

type cobraDumpFlag struct {
	Name                string `json:"name"`
	Shorthand           string `json:"shorthand"`
	Type                string `json:"type"`
	NoOptDefVal         string `json:"no_opt_def_val"`
	DefValue            string `json:"def_value"`
	Required            bool   `json:"required"`
	Hidden              bool   `json:"hidden"`
	Deprecated          string `json:"deprecated"`
	ShorthandDeprecated string `json:"shorthand_deprecated"`
}

type cobraDumpCmd struct {
	Path               string          `json:"path"`
	Name               string          `json:"name"`
	Aliases            []string        `json:"aliases"`
	SuggestFor         []string        `json:"suggest_for"`
	Hidden             bool            `json:"hidden"`
	Deprecated         string          `json:"deprecated"`
	Runnable           bool            `json:"runnable"`
	HasSubCommands     bool            `json:"has_subcommands"`
	DisableFlagParsing bool            `json:"disable_flag_parsing"`
	TraverseChildren   bool            `json:"traverse_children"`
	SilenceUsage       bool            `json:"silence_usage"`
	SilenceErrors      bool            `json:"silence_errors"`
	ArgsNil            bool            `json:"args_nil"`
	ArgsProbe          []*string       `json:"args_probe"`
	Local              []cobraDumpFlag `json:"local"`
	Persistent         []cobraDumpFlag `json:"persistent"`
	Help               cobraDumpFlag   `json:"help_flag"`
	Usage              string          `json:"usage"`
	HelpText           string          `json:"help"`
}

func cobraDumpFlagOf(f *pflag.Flag) cobraDumpFlag {
	req := false
	if v, ok := f.Annotations[cobra.BashCompOneRequiredFlag]; ok && len(v) > 0 && v[0] == "true" {
		req = true
	}
	return cobraDumpFlag{
		Name:                f.Name,
		Shorthand:           f.Shorthand,
		Type:                f.Value.Type(),
		NoOptDefVal:         f.NoOptDefVal,
		DefValue:            f.DefValue,
		Required:            req,
		Hidden:              f.Hidden,
		Deprecated:          f.Deprecated,
		ShorthandDeprecated: f.ShorthandDeprecated,
	}
}

func cobraDumpPath(c *cobra.Command) string {
	return strings.TrimPrefix(strings.TrimPrefix(c.CommandPath(), "goal"), " ")
}

func cobraDumpWalk(c *cobra.Command, out *[]*cobra.Command) {
	*out = append(*out, c)
	for _, s := range c.Commands() {
		cobraDumpWalk(s, out)
	}
}

func TestGoalCobraDump(t *testing.T) {
	dest := os.Getenv("GOAL_COBRA_DUMP_OUT")
	if dest == "" {
		t.Skip("GOAL_COBRA_DUMP_OUT not set")
	}
	// What cobra's ExecuteC adds to the root before it runs a command line.
	rootCmd.InitDefaultHelpCmd()
	rootCmd.InitDefaultCompletionCmd()
	var all []*cobra.Command
	cobraDumpWalk(rootCmd, &all)

	// Pass 1, before anything merges the persistent flags into Flags():
	// each command's own flags.
	dumps := make(map[*cobra.Command]*cobraDumpCmd)
	for _, c := range all {
		persistent := map[*pflag.Flag]bool{}
		for p := c; p != nil; p = p.Parent() {
			p.PersistentFlags().VisitAll(func(f *pflag.Flag) { persistent[f] = true })
		}
		d := &cobraDumpCmd{
			Path:               cobraDumpPath(c),
			Name:               c.Name(),
			Aliases:            append([]string{}, c.Aliases...),
			SuggestFor:         append([]string{}, c.SuggestFor...),
			Hidden:             c.Hidden,
			Deprecated:         c.Deprecated,
			Runnable:           c.Runnable(),
			HasSubCommands:     c.HasSubCommands(),
			DisableFlagParsing: c.DisableFlagParsing,
			TraverseChildren:   c.TraverseChildren,
			SilenceUsage:       c.SilenceUsage,
			SilenceErrors:      c.SilenceErrors,
			ArgsNil:            c.Args == nil,
			Local:              []cobraDumpFlag{},
			Persistent:         []cobraDumpFlag{},
		}
		c.Flags().VisitAll(func(f *pflag.Flag) {
			if !persistent[f] {
				d.Local = append(d.Local, cobraDumpFlagOf(f))
			}
		})
		c.PersistentFlags().VisitAll(func(f *pflag.Flag) {
			d.Persistent = append(d.Persistent, cobraDumpFlagOf(f))
		})
		if c.Args != nil {
			for n := 0; n <= 6; n++ {
				args := []string{}
				for i := 1; i <= n; i++ {
					args = append(args, fmt.Sprintf("a%d", i))
				}
				if err := c.Args(c, args); err != nil {
					s := err.Error()
					d.ArgsProbe = append(d.ArgsProbe, &s)
				} else {
					d.ArgsProbe = append(d.ArgsProbe, nil)
				}
			}
		}
		dumps[c] = d
	}

	// Pass 2: the help flag cobra's execute adds to the command it found,
	// then the usage it prints after an error and the help of `--help`.
	// A help function may change flags (`network pregen`'s hides the
	// inherited `rootdir`); a goal process prints one help only, so every
	// flag's `Hidden` is restored after each.
	hidden := map[*pflag.Flag]bool{}
	for _, c := range all {
		c.Flags().VisitAll(func(f *pflag.Flag) { hidden[f] = f.Hidden })
		c.PersistentFlags().VisitAll(func(f *pflag.Flag) { hidden[f] = f.Hidden })
	}
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	for _, c := range all {
		d := dumps[c]
		c.InitDefaultHelpFlag()
		d.Help = cobraDumpFlagOf(c.Flags().Lookup("help"))
		d.Usage = c.UsageString()
		buf.Reset()
		c.HelpFunc()(c, []string{})
		d.HelpText = buf.String()
		for f, h := range hidden {
			f.Hidden = h
		}
	}

	list := make([]*cobraDumpCmd, 0, len(all))
	for _, c := range all {
		list = append(list, dumps[c])
	}
	sort.SliceStable(list, func(i, j int) bool { return list[i].Path < list[j].Path })
	// The runes strconv.IsPrint rejects, which `%q` (strconv.Quote) escapes
	// in cobra's and pflag's errors: hex ranges "lo-hi", comma-separated.
	var notPrintable []string
	for r := rune(0); r <= 0x10ffff; r++ {
		if strconv.IsPrint(r) {
			continue
		}
		lo := r
		for r+1 <= 0x10ffff && !strconv.IsPrint(r+1) {
			r++
		}
		notPrintable = append(notPrintable, fmt.Sprintf("%x-%x", lo, r))
	}
	root := map[string]any{
		"not_printable":                strings.Join(notPrintable, ","),
		"disable_suggestions":          rootCmd.DisableSuggestions,
		"suggestions_minimum_distance": rootCmd.SuggestionsMinimumDistance,
		"commands":                     list,
	}
	b, err := json.MarshalIndent(root, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dest, append(b, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}
