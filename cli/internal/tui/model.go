package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"mxtools/internal/checks"
)

var (
	titleStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("42"))
	mutedStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
	okStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	warnStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	failStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("203"))
	infoStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("110"))
	boxStyle   = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("238")).Padding(0, 1)
)

type lookupMsg struct {
	results []checks.Result
	err     error
}

type Model struct {
	input    textinput.Model
	spin     spinner.Model
	viewport viewport.Model
	loading  bool
	results  []checks.Result
	err      string
	width    int
	height   int
	ready    bool
	history  []string
}

func New(initial string) Model {
	ti := textinput.New()
	ti.Placeholder = "example.com  |  mx:gmail.com  |  blacklist:1.1.1.1"
	ti.Focus()
	ti.CharLimit = 256
	ti.Width = 60
	if initial != "" {
		ti.SetValue(initial)
	}

	sp := spinner.New()
	sp.Spinner = spinner.Dot
	sp.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))

	return Model{input: ti, spin: sp}
}

func (m Model) Init() tea.Cmd {
	if strings.TrimSpace(m.input.Value()) != "" {
		return tea.Batch(m.spin.Tick, m.runLookup(m.input.Value()))
	}
	return textinput.Blink
}

func (m Model) runLookup(q string) tea.Cmd {
	return func() tea.Msg {
		parsed, err := checks.ParseQuery(q)
		if err != nil {
			return lookupMsg{err: err}
		}
		return lookupMsg{results: checks.Run(parsed)}
	}
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyCtrlC, tea.KeyEsc:
			if msg.Type == tea.KeyEsc && m.input.Focused() && m.input.Value() != "" {
				m.input.SetValue("")
				return m, nil
			}
			return m, tea.Quit
		case tea.KeyEnter:
			if m.loading {
				return m, nil
			}
			q := strings.TrimSpace(m.input.Value())
			if q == "" {
				return m, nil
			}
			m.loading = true
			m.err = ""
			m.results = nil
			m.history = prepend(m.history, q)
			return m, tea.Batch(m.spin.Tick, m.runLookup(q))
		case tea.KeyTab:
			// cycle nothing — keep simple
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		header := 8
		if !m.ready {
			m.viewport = viewport.New(msg.Width-2, max(5, msg.Height-header))
			m.ready = true
		} else {
			m.viewport.Width = msg.Width - 2
			m.viewport.Height = max(5, msg.Height-header)
		}
		m.input.Width = max(20, msg.Width-10)
		m.viewport.SetContent(m.renderResults())
		return m, nil

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spin, cmd = m.spin.Update(msg)
		if m.loading {
			return m, cmd
		}
		return m, nil

	case lookupMsg:
		m.loading = false
		if msg.err != nil {
			m.err = msg.err.Error()
		} else {
			m.results = msg.results
		}
		m.viewport.SetContent(m.renderResults())
		m.viewport.GotoTop()
		return m, nil
	}

	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	if m.ready {
		var vcmd tea.Cmd
		m.viewport, vcmd = m.viewport.Update(msg)
		return m, tea.Batch(cmd, vcmd)
	}
	return m, cmd
}

func (m Model) View() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("mx-tools"))
	b.WriteString(mutedStyle.Render("  private D.A.R.T.  ·  ↑/↓ scroll  ·  enter run  ·  esc/ctrl+c quit\n\n"))
	b.WriteString(m.input.View())
	b.WriteString("\n")
	if m.loading {
		b.WriteString("\n" + m.spin.View() + " running checks…\n")
	} else if m.err != "" {
		b.WriteString("\n" + failStyle.Render(m.err) + "\n")
	}
	if m.ready {
		b.WriteString("\n")
		b.WriteString(boxStyle.Width(max(20, m.width-2)).Render(m.viewport.View()))
	} else {
		b.WriteString("\n" + m.renderResults())
	}
	if len(m.history) > 0 {
		b.WriteString("\n" + mutedStyle.Render("recent: "+strings.Join(m.history[:min(5, len(m.history))], "  ·  ")))
	}
	return b.String()
}

func (m Model) renderResults() string {
	if len(m.results) == 0 && !m.loading && m.err == "" {
		return mutedStyle.Render("Enter a domain or command (mx:, spf:, blacklist:, smtp:, ping:, …)")
	}
	var b strings.Builder
	for i, r := range m.results {
		if i > 0 {
			b.WriteString("\n")
		}
		b.WriteString(titleStyle.Render(r.Title))
		b.WriteString(mutedStyle.Render(fmt.Sprintf("  %s  (%dms)\n", r.Query, r.ElapsedMs)))
		b.WriteString(mutedStyle.Render(r.Summary) + "\n")
		for _, row := range r.Rows {
			b.WriteString(fmt.Sprintf("  %s  %-22s  %s", statusPaint(row.Status), truncate(row.Name, 22), row.Value))
			if row.Info != "" {
				b.WriteString(mutedStyle.Render("  "+row.Info))
			}
			b.WriteString("\n")
		}
	}
	return b.String()
}

func statusPaint(s checks.Severity) string {
	label := string(s)
	switch s {
	case checks.StatusOK:
		return okStyle.Render(label)
	case checks.StatusWarn:
		return warnStyle.Render(label)
	case checks.StatusFail, checks.StatusError:
		return failStyle.Render(label)
	default:
		return infoStyle.Render(label)
	}
}

func prepend(list []string, v string) []string {
	out := []string{v}
	for _, x := range list {
		if x != v {
			out = append(out, x)
		}
	}
	if len(out) > 20 {
		out = out[:20]
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
