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

const parentDirLabel = "← Parent directory"

// Picker is the keyboard-driven file picker, PRD 8.2 and key map 8.4.
// Parent navigation is a list row (matching the UI proposal) so ←/→ can
// drive the horizontal home tabs instead of the directory tree.
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
	hasParent   bool

	width  int
	height int
	th     theme
}

func NewPicker(title, action, start string, th theme) *Picker {
	if start == "" {
		start = "."
	}
	abs, err := filepath.Abs(start)
	if err == nil {
		start = abs
	}
	p := &Picker{title: title, action: action, dir: start, th: th, width: maxWidth, height: maxHeight}
	p.filterInput = textinput.New()
	p.filterInput.Placeholder = "filter"
	p.reload()
	return p
}

func (p *Picker) reload() {
	parent := filepath.Dir(p.dir)
	p.hasParent = parent != p.dir

	entries, err := os.ReadDir(p.dir)
	if err != nil {
		p.entries = nil
		return
	}
	// Dotfiles and dot-directories (.config, .git, ...) stay hidden; the
	// picker shows conventional files only.
	visible := entries[:0]
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), ".") {
			visible = append(visible, e)
		}
	}
	entries = visible
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
	n := p.rowCount()
	if p.cursor >= n {
		p.cursor = max(0, n-1)
	}
}

func (p *Picker) rowCount() int {
	n := len(p.entries)
	if p.hasParent {
		n++
	}
	return n
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
		if p.cursor < p.rowCount()-1 {
			p.cursor++
		}
	case "backspace":
		p.goParent()
	case "enter":
		return p.activateRow()
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

func (p *Picker) goParent() {
	if !p.hasParent {
		return
	}
	p.dir = filepath.Dir(p.dir)
	p.cursor = 0
	p.reload()
}

func (p *Picker) activateRow() (tea.Model, tea.Cmd) {
	if p.hasParent && p.cursor == 0 {
		p.goParent()
		return p, nil
	}
	idx := p.cursor
	if p.hasParent {
		idx--
	}
	if idx < 0 || idx >= len(p.entries) {
		return p, nil
	}
	e := p.entries[idx]
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

// ContentView is the list body for embedding inside the home content box.
func (p *Picker) ContentView(maxRows int) string {
	var b strings.Builder
	b.WriteString(p.title + "\n")
	if maxRows < 1 {
		maxRows = 1
	}
	// Title uses one row; remaining rows are the list (+ optional filter).
	listRows := maxRows - 1
	if p.filtering || p.filter != "" {
		listRows--
	}
	if listRows < 1 {
		listRows = 1
	}

	n := p.rowCount()
	start := 0
	if p.cursor >= listRows {
		start = p.cursor - listRows + 1
	}
	for i := start; i < n && i < start+listRows; i++ {
		label := p.rowLabel(i)
		if i == p.cursor {
			b.WriteString("> " + p.th.selected.Render(label) + "\n")
		} else {
			b.WriteString("  " + label + "\n")
		}
	}
	if p.filtering {
		b.WriteString("/filter: " + p.filterInput.View())
	} else if p.filter != "" {
		b.WriteString(p.th.dim.Render("filter: " + p.filter))
	}
	return strings.TrimRight(b.String(), "\n")
}

func (p *Picker) rowLabel(i int) string {
	if p.hasParent && i == 0 {
		return parentDirLabel
	}
	idx := i
	if p.hasParent {
		idx--
	}
	e := p.entries[idx]
	name := e.Name()
	if e.IsDir() {
		name += "/"
	}
	return name
}

// View is a standalone picker screen (used by tests and fallbacks).
func (p *Picker) View() string {
	var b strings.Builder
	b.WriteString(p.th.title.Render(p.title))
	b.WriteString("\n" + p.th.dim.Render(p.dir) + "\n\n")
	maxRows := p.height - 8
	b.WriteString(p.ContentView(maxRows))
	b.WriteString("\n")
	if p.showHelp {
		b.WriteString("\n" + renderKeys(p.th, "{↑}/{↓} move • {Enter} select • {Backspace} parent • {/} filter • {?} help • {Esc} back") + "\n")
	}
	b.WriteString("\n" + renderKeys(p.th, "{Esc} back • {Ctrl+C} quit"))
	return fit(b.String(), p.width, p.height)
}
