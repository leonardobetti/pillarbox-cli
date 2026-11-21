package tui

import (
	"os"
	"strings"

	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/leonardobetti/pillarbox-cli/internal/keystore"
)

type screen int

const (
	screenWelcome screen = iota
	screenKeyType
	screenGate
)

type modeItem string

func (m modeItem) FilterValue() string { return string(m) }
func (m modeItem) Title() string       { return string(m) }
func (m modeItem) Description() string { return "" }

// Onboarding is the first-run flow: welcome, key type, gate-encrypt toggle.
// It writes only settings.json, once the gate screen is applied, so Esc at
// any earlier screen leaves no file behind. Secrets are never collected
// here; each file gets its own key at encrypt time.
type Onboarding struct {
	deps *Deps
	th   theme

	screen   screen
	width    int
	height   int
	modeList list.Model
	mode     keystore.Mode
	gateVal  bool
	errMsg   string
}

func NewOnboarding(d *Deps) *Onboarding {
	th := newTheme(os.Stdout)
	modes := []list.Item{
		modeItem(keystore.ModePassword),
		modeItem(keystore.ModePIN),
		modeItem(keystore.ModePassword2FA),
		modeItem(keystore.ModePIN2FA),
	}
	l := list.New(modes, list.NewDefaultDelegate(), maxWidth, 6)
	l.Title = "Key type for new files"
	l.SetShowHelp(false)
	l.SetShowStatusBar(false)
	l.SetShowPagination(false)
	l.SetFilteringEnabled(false)
	return &Onboarding{deps: d, th: th, width: maxWidth, height: maxHeight, modeList: l}
}

func (m *Onboarding) Init() tea.Cmd { return nil }

func (m *Onboarding) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.modeList.SetSize(msg.Width, msg.Height-10)
		return m, nil
	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyCtrlC:
			return m, tea.Quit
		case tea.KeyEsc:
			if m.screen == screenWelcome {
				return m, tea.Quit
			}
			m.screen--
			m.errMsg = ""
			return m, nil
		}
	}

	switch m.screen {
	case screenWelcome:
		if k, ok := msg.(tea.KeyMsg); ok {
			if k.Type == tea.KeyEnter || k.Type == tea.KeySpace {
				m.screen = screenKeyType
			} else if k.String() == "q" {
				return m, tea.Quit
			}
		}
	case screenKeyType:
		var cmd tea.Cmd
		m.modeList, cmd = m.modeList.Update(msg)
		if k, ok := msg.(tea.KeyMsg); ok {
			if k.String() == "q" {
				return m, tea.Quit
			}
			if k.Type == tea.KeyEnter {
				if it, ok := m.modeList.SelectedItem().(modeItem); ok {
					m.mode = keystore.Mode(it)
					m.screen = screenGate
				}
			}
		}
		return m, cmd
	case screenGate:
		if k, ok := msg.(tea.KeyMsg); ok {
			switch k.String() {
			case "backspace", "left", "right", "h", "l", "space":
				m.gateVal = !m.gateVal
				return m, nil
			case "a", "enter":
				return m, m.save()
			case "q":
				return m, tea.Quit
			}
		}
	}
	return m, nil
}

// save writes settings.json exactly once, then quits.
func (m *Onboarding) save() tea.Cmd {
	st := &keystore.Settings{KeyType: m.mode, GateEncrypt: m.gateVal}
	if err := m.deps.Settings.Save(st); err != nil {
		m.errMsg = "cannot write settings"
		return nil
	}
	return tea.Quit
}

func (m *Onboarding) View() string {
	var b strings.Builder
	switch m.screen {
	case screenWelcome:
		b.WriteString(m.th.title.Render("Welcome to Pillarbox"))
		b.WriteString("\n\nEncrypt and decrypt files from the terminal.\n\n")
		b.WriteString("Commands to know: lock <path>, unlock <file.pbx>\n\n")
		b.WriteString(m.th.dim.Render("Press enter to continue"))
	case screenKeyType:
		b.WriteString(m.th.title.Render("Choose the key type for new files"))
		b.WriteString("\n\n")
		b.WriteString(m.modeList.View())
	case screenGate:
		toggle := "no"
		if m.gateVal {
			toggle = "yes"
		}
		b.WriteString(m.th.title.Render("Settings"))
		b.WriteString("\n\nRequire authentication to encrypt (gate-encrypt): " + toggle + "\n")
		b.WriteString("\n" + m.th.dim.Render("backspace toggle • a apply • esc back • q quit"))
	}
	if m.errMsg != "" {
		b.WriteString("\n" + m.th.errS.Render(m.errMsg) + "\n")
	}
	footer := "↑/↓ or tab navigate • enter continue • esc back • q quit • ctrl+c abort"
	if m.screen == screenGate {
		footer = "backspace toggle • a apply • esc back • q quit • ctrl+c abort"
	}
	b.WriteString("\n" + m.th.dim.Render(footer))
	return fit(b.String(), m.width, m.height)
}
