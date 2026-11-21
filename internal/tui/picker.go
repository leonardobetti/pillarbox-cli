package tui

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

type pickedMsg struct {
	action string
	path   string
}

type pickerCancelledMsg struct{}

// Picker is the keyboard-driven file picker, PRD 8.2 and key map 8.4.
type Picker struct {
	title  string
	action string
	dir    string

	entries     []os.DirEntry
	cursor      int
	filter      string
	filtering   bool
	filterInput textinput.Model
	showHelp    bool

	width  int
	height int
	th     theme
}

func NewPicker(title, action, start string, th theme) *Picker {
	if start == "" {
		start = "."
	}
	p := &Picker{title: title, action: action, dir: start, th: th, width: maxWidth, height: maxHeight}
	p.filterInput = textinput.New()
	p.filterInput.Placeholder = "filter"
	p.reload()
	return p
}

func (p *Picker) reload() {
	entries, err := os.ReadDir(p.dir)
	if err != nil {
		p.entries = nil
		return
	}
	sort.SliceStable(entries, func(i, j int) bool {
		di, dj := entries[i].IsDir(), entries[j].IsDir()
		if di != dj {
			return di
		}
		return entries[i].Name() < entries[j].Name()
	})
	if p.filter != "" {
		var kept []os.DirEntry
		for _, e := range entries {
			if strings.Contains(e.Name(), p.filter) {
				kept = append(kept, e)
			}
		}
		entries = kept
	}
	p.entries = entries
	if p.cursor >= len(p.entries) {
		p.cursor = max(0, len(p.entries)-1)
	}
}

func (p *Picker) Init() tea.Cmd { return nil }

func (p *Picker) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if p.filtering {
		if k, ok := msg.(tea.KeyMsg); ok {
			if k.Type == tea.KeyEnter {
				p.filter = p.filterInput.Value()
				p.filtering = false
				p.filterInput.Blur()
				p.reload()
				return p, nil
			}
			if k.Type == tea.KeyEsc {
				p.filtering = false
				p.filterInput.Blur()
				p.filterInput.SetValue("")
				p.filter = ""
				p.reload()
				return p, nil
			}
		}
		var cmd tea.Cmd
		p.filterInput, cmd = p.filterInput.Update(msg)
		return p, cmd
	}

	k, ok := msg.(tea.KeyMsg)
	if !ok {
		return p, nil
	}
	switch k.String() {
	case "up", "k":
		if p.cursor > 0 {
			p.cursor--
		}
	case "down", "j":
		if p.cursor < len(p.entries)-1 {
			p.cursor++
		}
	case "left", "h":
		parent := filepath.Dir(p.dir)
		if parent != p.dir {
			p.dir = parent
			p.cursor = 0
			p.reload()
		}
	case "right", "l", "enter":
		if p.cursor < len(p.entries) {
			e := p.entries[p.cursor]
			full := filepath.Join(p.dir, e.Name())
			if e.IsDir() {
				p.dir = full
				p.cursor = 0
				p.reload()
				return p, nil
			}
			action := p.action
			return p, func() tea.Msg { return pickedMsg{action: action, path: full} }
		}
	case "esc":
		return p, func() tea.Msg { return pickerCancelledMsg{} }
	case "/":
		p.filtering = true
		return p, p.filterInput.Focus()
	case "?":
		p.showHelp = !p.showHelp
	case "ctrl+c":
		return p, tea.Quit
	}
	return p, nil
}

func (p *Picker) View() string {
	var b strings.Builder
	b.WriteString(p.th.title.Render(p.title))
	b.WriteString("\n" + p.th.dim.Render(p.dir) + "\n\n")
	maxRows := p.height - 8
	if maxRows < 1 {
		maxRows = 1
	}
	start := 0
	if p.cursor >= maxRows {
		start = p.cursor - maxRows + 1
	}
	for i := start; i < len(p.entries) && i < start+maxRows; i++ {
		e := p.entries[i]
		name := e.Name()
		if e.IsDir() {
			name += "/"
		}
		if i == p.cursor {
			b.WriteString("> " + name + "\n")
		} else {
			b.WriteString("  " + name + "\n")
		}
	}
	if p.filtering {
		b.WriteString("\n/filter: " + p.filterInput.View() + "\n")
	} else if p.filter != "" {
		b.WriteString("\n" + p.th.dim.Render("filter: "+p.filter) + "\n")
	}
	if p.showHelp {
		b.WriteString("\n" + p.th.dim.Render("↑/↓ move • ←/→ parent/enter • enter select • / filter • ? help • esc back") + "\n")
	}
	b.WriteString("\n" + p.th.dim.Render("esc back • ctrl+c quit"))
	return fit(b.String(), p.width, p.height)
}
