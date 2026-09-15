package main

import (
	"fmt"
	"sort"
	"strings"
)

// ================================================================
// Machine-readable catalogs (--list-vectors --json, --list-sources,
// --explain --json)
// ================================================================
//
// The documentation modes already speak human (terminal text); this file
// gives them a machine voice with the SAME honesty contract: every list is
// rendered from the binary's own tables (vectorCatalogOrder, validSources,
// explainDB) in a canonical order, so a consumer can diff two invocations
// byte for byte and a new vector or source appears in the JSON without any
// documentation edit. Zero host data flows into these documents — they are
// pure functions of the binary's tables.

// catalogDoc is the envelope shared by every machine-readable catalog: the
// mode field lets a consumer route the document without sniffing keys, the
// same trick the SARIF export uses with its $schema.
type catalogDoc struct {
	Tool    string `json:"tool"`
	Version string `json:"version"`
	Mode    string `json:"mode"`
}

// catalogVector is one row of the --list-vectors --json payload.
type catalogVector struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// vectorCatalogJSON builds the machine-readable vector catalog: the
// canonical vectorCatalogOrder (pinned to validVectors by test), each entry
// with the same one-line description the text mode prints. Order is
// deterministic by construction — never map iteration.
func vectorCatalogJSON() []byte {
	type doc struct {
		catalogDoc
		Vectors []catalogVector `json:"vectors"`
	}
	out := doc{catalogDoc: catalogDoc{
		Tool:    "Auto-Privilege",
		Version: Version,
		Mode:    "vector-catalog",
	}}
	for _, name := range vectorCatalogOrder {
		desc := "(no catalog entry — report it)"
		if v, ok := vectorCatalog[name]; ok {
			desc = v.Desc
		}
		out.Vectors = append(out.Vectors, catalogVector{Name: name, Description: desc})
	}
	data, err := marshalJSON(out)
	if err != nil {
		// Unreachable: strings and slices only. Stay honest rather than
		// printing a half document.
		return []byte(`{"error":"vector catalog marshal failed"}`)
	}
	return data
}

// printVectorListJSON emits the vector catalog as JSON on stdout.
func printVectorListJSON() {
	fmt.Println(string(vectorCatalogJSON()))
}

// catalogSource is one row of the --list-sources payload: the finding-source
// vocabulary with its meaning, taken verbatim from the playbook DB so the
// list can never describe a source differently from --explain.
type catalogSource struct {
	Source      string `json:"source"`
	Description string `json:"description"`
}

// sourceCatalog renders the source vocabulary in canonical (validSources)
// order. Descriptions come from explainDB — the table TestExplainDBCovers-
// AllSources pins to validSources — so the three surfaces that name sources
// (--ignore validation, --explain playbooks, this list) share one source of
// truth and cannot drift apart.
func sourceCatalog() []catalogSource {
	out := make([]catalogSource, 0, len(validSources))
	for _, src := range validSources {
		desc := "no playbook entry yet (report it)"
		if e, ok := explainDB[src]; ok {
			desc = e.What
		}
		out = append(out, catalogSource{Source: src, Description: desc})
	}
	return out
}

// printSourceList is the text voice of --list-sources: the vocabulary
// --ignore and --explain accept, one honest line per source. Documentation
// mode like --list-vectors — print and exit, no scan.
func printSourceList() {
	fmt.Printf("  %s (%d sources — the --ignore / --explain vocabulary)\n\n",
		colorize("── Finding sources ──", AnsiCyan), len(validSources))
	for _, s := range sourceCatalog() {
		fmt.Printf("  %-10s %s\n", colorize(s.Source, AnsiBold), s.Description)
	}
	fmt.Println()
	fmt.Println(colorize("  usage: --ignore <SRC[,SRC2,…]> excludes sources  ·  --explain <src> prints its playbook", AnsiGrey))
}

// buildSourceListJSONDoc builds the --list-sources --json document (pure —
// the printer is a thin wrapper, tests pin the shape without stdout capture).
type sourceListJSONDoc struct {
	catalogDoc
	Sources []catalogSource `json:"sources"`
}

func buildSourceListJSONDoc() sourceListJSONDoc {
	out := sourceListJSONDoc{catalogDoc: catalogDoc{
		Tool:    "Auto-Privilege",
		Version: Version,
		Mode:    "sources",
	}}
	out.Sources = sourceCatalog()
	return out
}

// printSourceListJSON emits the source vocabulary as JSON on stdout.
func printSourceListJSON() {
	data, err := marshalJSON(buildSourceListJSONDoc())
	if err != nil {
		return
	}
	fmt.Println(string(data))
}

// explainJSONDoc is the machine-readable playbook: one entry per source,
// the remediation steps as a JSON array instead of indented arrows — the
// shape a CI dashboard or a hardening tracker can ingest directly.
type explainJSONDoc struct {
	Source string   `json:"source"`
	What   string   `json:"what"`
	Steps  []string `json:"steps"`
}

// explainJSONDocFor builds the structured playbook document (pure — same
// argument contract as printExplain; tests pin it without stdout capture).
// "all" keeps the alphabetical order the text mode uses; unknown sources
// are the same error the text mode returns (exit 2 at the caller) — the
// JSON voice never invents advice either.
type explainJSONRoot struct {
	catalogDoc
	Scope     string           `json:"scope"`
	Playbooks []explainJSONDoc `json:"playbooks"`
}

func explainJSONDocFor(source string) (explainJSONRoot, error) {
	out := explainJSONRoot{catalogDoc: catalogDoc{
		Tool:    "Auto-Privilege",
		Version: Version,
		Mode:    "explain",
	}}
	appendOne := func(src string) {
		e, ok := explainDB[src]
		if !ok {
			// Defensive: validation upstream guarantees presence, but the
			// JSON must stay honest if the DB and the list ever diverge —
			// empty steps, the same marker the text printer uses.
			out.Playbooks = append(out.Playbooks, explainJSONDoc{Source: src, What: "no playbook entry yet (report it)", Steps: []string{}})
			return
		}
		steps := append([]string{}, e.Harden...)
		if steps == nil {
			steps = []string{}
		}
		out.Playbooks = append(out.Playbooks, explainJSONDoc{Source: src, What: e.What, Steps: steps})
	}
	if strings.EqualFold(source, "all") {
		out.Scope = "all"
		sources := append([]string{}, validSources...)
		sort.Strings(sources)
		for _, s := range sources {
			appendOne(s)
		}
		return out, nil
	}
	src := strings.ToUpper(strings.TrimSpace(source))
	if !isValidSource(src) {
		return out, fmt.Errorf("unknown source %q (valid: %s,all)", source, strings.Join(validSources, ","))
	}
	out.Scope = src
	appendOne(src)
	return out, nil
}

// printExplainJSON emits the structured playbook as JSON on stdout.
func printExplainJSON(source string) error {
	doc, err := explainJSONDocFor(source)
	if err != nil {
		return err
	}
	data, err := marshalJSON(doc)
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}
