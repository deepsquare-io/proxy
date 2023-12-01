package ssh

import (
	"fmt"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"
)

var primaryColor = lipgloss.Color("#9202de")
var borderStyle = lipgloss.NewStyle().Foreground(primaryColor).Padding(1)

func renderOutput(route string, domain string, port int64) string {
	rows := [][]string{
		{"HTTP", fmt.Sprintf("http://%s.%s", route, domain)},
		{"HTTPS", fmt.Sprintf("https://%s.%s", route, domain)},
		{"TCP", fmt.Sprintf("tcp://%s:%d", domain, port)},
	}

	return table.New().
		Border(lipgloss.NormalBorder()).
		BorderStyle(borderStyle).
		Headers("Protocol", "URL").
		Rows(rows...).
		Render() +
		"\n"
}
