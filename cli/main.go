package main

import (
	"encoding/json"
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"

	"mxtools/internal/checks"
	"mxtools/internal/tui"
)

func main() {
	args := os.Args[1:]
	jsonOut := false
	oneshot := false
	filtered := make([]string, 0, len(args))
	for _, a := range args {
		switch a {
		case "--json":
			jsonOut = true
			oneshot = true
		case "--once", "-1":
			oneshot = true
		case "-h", "--help":
			printHelp()
			return
		default:
			filtered = append(filtered, a)
		}
	}

	query := ""
	if len(filtered) > 0 {
		query = filtered[0]
	}

	if oneshot || jsonOut {
		if query == "" {
			fmt.Fprintln(os.Stderr, "usage: mx [--json] <query>")
			os.Exit(2)
		}
		parsed, err := checks.ParseQuery(query)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		results := checks.Run(parsed)
		if jsonOut {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			_ = enc.Encode(map[string]any{"query": query, "results": results})
			return
		}
		for _, r := range results {
			fmt.Printf("== %s (%s) [%dms]\n%s\n", r.Title, r.Query, r.ElapsedMs, r.Summary)
			for _, row := range r.Rows {
				fmt.Printf("  [%s] %s: %s\n", row.Status, row.Name, row.Value)
			}
			fmt.Println()
		}
		return
	}

	m := tui.New(query)
	p := tea.NewProgram(m, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func printHelp() {
	fmt.Println(`mx-tools CLI — private SuperTool

Usage:
  mx                  Interactive TUI
  mx example.com      TUI prefilled / auto-run
  mx --once mx:a.com  One-shot text output
  mx --json spf:a.com JSON output

Commands (prefix:target):
  auto full
  a aaaa cname mx ns ptr soa txt
  spf dmarc dkim bimi mta-sts tlsrpt
  blacklist dns whois arin asn
  http https tcp smtp ping trace

Examples:
  mx example.com
  mx blacklist:127.0.0.2
  mx dkim:google:gmail.com
  mx tcp:example.com:443
  mx smtp:gmail.com`)
}
