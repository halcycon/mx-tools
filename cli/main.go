package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"mxtools/internal/agent"
	"mxtools/internal/checks"
	"mxtools/internal/tui"
)

func main() {
	args := os.Args[1:]
	if len(args) > 0 && args[0] == "agent" {
		if err := runAgent(args[1:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

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
	if strings.EqualFold(query, "headers") && len(filtered) > 1 {
		query = "headers:" + filtered[1]
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

func runAgent(args []string) error {
	cfg := agent.Config{Listen: "127.0.0.1:8788"}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-h" || a == "--help":
			printAgentHelp()
			return nil
		case a == "--allow-lan":
			cfg.AllowLAN = true
		case a == "--listen" && i+1 < len(args):
			i++
			cfg.Listen = args[i]
		case strings.HasPrefix(a, "--listen="):
			cfg.Listen = strings.TrimPrefix(a, "--listen=")
		case a == "--token" && i+1 < len(args):
			i++
			cfg.Token = args[i]
		case strings.HasPrefix(a, "--token="):
			cfg.Token = strings.TrimPrefix(a, "--token=")
		default:
			return fmt.Errorf("unknown agent flag: %s\n\nrun: mx agent --help", a)
		}
	}
	if env := strings.TrimSpace(os.Getenv("MX_AGENT_TOKEN")); cfg.Token == "" && env != "" {
		cfg.Token = env
	}
	return agent.Run(cfg)
}

func printAgentHelp() {
	fmt.Println(`mx agent — local probe HTTP server for the D.A.R.T. web UI

Runs the same checks as the CLI on this machine (local DNS, SMTP :25, ping).
Point the web UI Settings → Probe agent at the listen URL + token.

Usage:
  mx agent [--listen 127.0.0.1:8788] [--token SECRET] [--allow-lan]

Flags:
  --listen ADDR   Bind address (default 127.0.0.1:8788)
  --token SECRET  Bearer token (or MX_AGENT_TOKEN). Auto-generated if omitted.
  --allow-lan     Required to bind a non-loopback address

Env:
  MX_AGENT_TOKEN      Same as --token
  SPAMHAUS_DQS_KEY    Optional DQS key for Spamhaus (stays on this host)

Examples:
  mx agent
  mx agent --token "$(openssl rand -hex 24)"
  export SPAMHAUS_DQS_KEY=... MX_AGENT_TOKEN=...
  mx agent --listen 0.0.0.0:8788 --allow-lan

Web UI: Settings → Probe agent URL http://127.0.0.1:8788 + paste token.
From an https:// hosted UI, some browsers block http://127.0.0.1 (mixed content);
use local wrangler/vite, or SSH tunnel + loopback.`)
}

func printHelp() {
	fmt.Println(`mx-tools CLI — private D.A.R.T.

Usage:
  mx                  Interactive TUI
  mx example.com      TUI prefilled / auto-run
  mx --once mx:a.com  One-shot text output
  mx --json spf-flat:a.com JSON output
  mx agent            Local probe server for the web UI

Commands (prefix:target):
  auto full
  a aaaa cname mx ns ptr soa txt
  spf spf-flat dmarc dkim bimi mta-sts tlsrpt
  blacklist dns whois arin asn
  http https tcp smtp ping trace
  headers

Examples:
  mx example.com
  mx blacklist:127.0.0.2
  mx --once headers message.eml
  mx --json headers < headers.txt
  mx dkim:google:gmail.com
  mx tcp:example.com:443
  mx smtp:smtp.gmail.com
  mx agent --token secret

Spamhaus DQS (private):
  export SPAMHAUS_DQS_KEY=...

See also: mx agent --help`)
}
