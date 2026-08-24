package checks

import "time"

type Severity string

const (
	StatusOK          Severity = "ok"
	StatusInfo        Severity = "info"
	StatusWarn        Severity = "warn"
	StatusFail        Severity = "fail"
	StatusError       Severity = "error"
	StatusUnsupported Severity = "unsupported"
)

type Row struct {
	Status Severity `json:"status"`
	Name   string   `json:"name"`
	Value  string   `json:"value"`
	Info   string   `json:"info,omitempty"`
}

type Related struct {
	Tool  string `json:"tool"`
	Label string `json:"label"`
	Query string `json:"query"`
}

type Result struct {
	Tool      string    `json:"tool"`
	Title     string    `json:"title"`
	Query     string    `json:"query"`
	OK        bool      `json:"ok"`
	Summary   string    `json:"summary"`
	Rows      []Row     `json:"rows"`
	Related   []Related `json:"related,omitempty"`
	ElapsedMs int64     `json:"elapsedMs"`
}

type ParsedQuery struct {
	Tool   string
	Target string
	Extra  string
}

func Base(tool, title, query string, rows []Row, summary string, start time.Time, ok bool) Result {
	return Result{
		Tool:      tool,
		Title:     title,
		Query:     query,
		OK:        ok,
		Summary:   summary,
		Rows:      rows,
		ElapsedMs: time.Since(start).Milliseconds(),
	}
}
