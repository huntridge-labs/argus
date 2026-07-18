// Package main is an intentionally-vulnerable Go fixture used only by the
// scanner-govulncheck E2E test (.github/workflows/test-actions.yml).
//
// It calls golang.org/x/text/language.ParseAcceptLanguage from a pinned
// vulnerable dependency (golang.org/x/text v0.3.7) so that GO-2022-1059 is
// *reachable* — exercising govulncheck's call-graph analysis end to end, not
// just its presence-based detection. See go.mod for the advisory details.
package main

import (
	"fmt"

	"golang.org/x/text/language"
)

func main() {
	// ParseAcceptLanguage is the vulnerable symbol for GO-2022-1059.
	tags, _, err := language.ParseAcceptLanguage("en-US,en;q=0.9,de;q=0.8")
	if err != nil {
		fmt.Println("parse error:", err)
		return
	}
	fmt.Println("parsed language tags:", tags)
}
