package tui

import (
	"errors"
	"os"
	"strings"

	"filippo.io/age"
	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"

	"github.com/leonardobetti/pillarbox-cli/internal/auth"
	"github.com/leonardobetti/pillarbox-cli/internal/keystore"
	"github.com/leonardobetti/pillarbox-cli/internal/vault"
)

type homeScreen int

const (
	homeMenu homeScreen = iota
	homePicker
	homeSecret
	homeStatus
	homeSettings
	homeHelp
	homeResult
)

type menuItem string

func (m menuItem) FilterValue() string { return string(m) }
func (m menuItem) Title() string       { return string(m) }
func (m menuItem) Description() string { return "" }

type promptDoneMsg struct {
	action   string
	identity []byte
	newStep  int64
}

type promptCancelledMsg struct{}

// Home is the home menu of PRD 8.2: Encrypt, Decrypt, Status, Settings, Help.
type Home struct {
	deps   *Deps
	th     theme
	screen homeScreen

	width, height int
	menu          list.Model

	ks    *keystore.Keystore
	ksErr string

	picker   *Picker
	prompt   *secretPrompt
	identity []byte

	statusText   string
	settingsForm *huh.Form
	gateVal      bool

	result      string
	resultIsErr bool
}

const helpText = "↑/↓ or k/j move • ←/→ or h/l parent/enter folder • enter select • esc back • / filter • ? help • q quit • ctrl+c abort"

func NewHome(d *Deps) *Home {
	th := newTheme(os.Stdout)
	items := []list.Item{
		menuItem("Encrypt"),
		menuItem("Decrypt"),
		menuItem("Status"),
		menuItem("Settings"),
		menuItem("Help"),
	}
	del := list.NewDefaultDelegate()
	del.ShowDescription = false
	l := list.New(items, del, maxWidth, 8)
	l.Title = "Pillarbox"
	l.SetShowHelp(false)
	l.SetShowStatusBar(false)
	l.SetShowPagination(false)
	h := &Home{deps: d, th: th, screen: homeMenu, width: maxWidth, height: maxHeight, menu: l}
	h.reloadKeystore()
	return h
}

func (m *Home) reloadKeystore() {
	ks, err := m.deps.Store.Load()
	if err != nil {
		m.ks = nil
		m.ksErr = "keystore missing or invalid; run pillarbox init"
		return
	}
	m.ks = ks
}

func (m *Home) Init() tea.Cmd { return nil }

func (m *Home) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.menu.SetSize(msg.Width, msg.Height-8)
		if m.picker != nil {
			m.picker.width, m.picker.height = msg.Width, msg.Height
		}
		return m, nil
	case pickedMsg:
		m.runPicked(msg)
		return m, nil
	case promptDoneMsg:
		m.identity = msg.identity
		if m.ks != nil && m.ks.Mode.Has2FA() {
			m.ks.LastTOTPStep = &msg.newStep
			if err := m.deps.Store.Save(m.ks); err != nil {
				m.setResult("", err)
				return m, nil
			}
		}
		m.openPicker(msg.action)
		return m, nil
	case promptCancelledMsg, pickerCancelledMsg:
		m.screen = homeMenu
		return m, nil
	case tea.KeyMsg:
		if msg.Type == tea.KeyCtrlC {
			return m, tea.Quit
		}
		if msg.Type == tea.KeyEsc {
			if m.screen == homeMenu {
				return m, tea.Quit
			}
			m.screen = homeMenu
			return m, nil
		}
		if m.screen == homeMenu {
			if msg.String() == "q" {
				return m, tea.Quit
			}
			return m.updateMenu(msg)
		}
		switch m.screen {
		case homePicker:
			up, cmd := m.picker.Update(msg)
			if p, ok := up.(*Picker); ok {
				m.picker = p
			}
			return m, cmd
		case homeSecret:
			up, cmd := m.prompt.Update(msg)
			if p, ok := up.(*secretPrompt); ok {
				m.prompt = p
			}
			return m, cmd
		case homeSettings:
			updated, cmd := m.settingsForm.Update(msg)
			if f, ok := updated.(*huh.Form); ok {
				m.settingsForm = f
			}
			if m.settingsForm.State == huh.StateCompleted {
				m.ks.Policy.GateEncrypt = m.gateVal
				if err := m.deps.Store.Save(m.ks); err != nil {
					m.setResult("", err)
					return m, nil
				}
				m.screen = homeMenu
			}
			return m, cmd
		case homeStatus, homeHelp, homeResult:
			m.screen = homeMenu
			return m, nil
		}
	}
	return m, nil
}

func (m *Home) updateMenu(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	m.menu, cmd = m.menu.Update(msg)
	if msg.Type != tea.KeyEnter {
		return m, cmd
	}
	it, ok := m.menu.SelectedItem().(menuItem)
	if !ok {
		return m, cmd
	}
	switch it {
	case "Encrypt":
		if m.ks == nil {
			m.setResult("", errors.New(m.ksErr))
			return m, nil
		}
		if m.ks.Policy.GateEncrypt {
			m.openPrompt("lock")
		} else {
			m.openPicker("lock")
		}
	case "Decrypt":
		if m.ks == nil {
			m.setResult("", errors.New(m.ksErr))
			return m, nil
		}
		m.openPrompt("unlock")
	case "Status":
		m.statusText = m.statusView()
		m.screen = homeStatus
	case "Settings":
		if m.ks == nil {
			m.setResult("", errors.New(m.ksErr))
			return m, nil
		}
		m.gateVal = m.ks.Policy.GateEncrypt
		m.settingsForm = huh.NewForm(huh.NewGroup(
			huh.NewConfirm().
				Title("Require authentication to encrypt (gate-encrypt)?").
				Affirmative("Yes").Negative("No").
				Value(&m.gateVal),
		))
		m.screen = homeSettings
		return m, m.settingsForm.Init()
	case "Help":
		m.screen = homeHelp
	}
	return m, cmd
}

func (m *Home) openPicker(action string) {
	title := "Lock — select a file or folder"
	if action == "unlock" {
		title = "Unlock — select a .pbx file"
	}
	m.picker = NewPicker(title, action, m.deps.StartDir, m.th)
	m.screen = homePicker
}

func (m *Home) openPrompt(action string) {
	m.prompt = newSecretPrompt(m.deps, m.ks, action)
	m.screen = homeSecret
}

func (m *Home) runPicked(msg pickedMsg) {
	if m.ks == nil {
		m.setResult("", errors.New(m.ksErr))
		return
	}
	switch msg.action {
	case "lock":
		dst, err := m.deps.Vault.Lock(msg.path, m.ks.Recipient, vault.LockOptions{})
		m.setResult(dst, err)
	case "unlock":
		id, err := age.ParseX25519Identity(string(m.identity))
		if err != nil {
			m.setResult("", err)
			return
		}
		dst, err := m.deps.Vault.Unlock(msg.path, id, vault.UnlockOptions{})
		m.setResult(dst, err)
	}
}

func (m *Home) setResult(dst string, err error) {
	if err != nil {
		m.result = err.Error()
		m.resultIsErr = true
	} else {
		m.result = "wrote " + dst
		m.resultIsErr = false
	}
	m.screen = homeResult
}

// statusView prints no secret, seed or key, FR-13.
func (m *Home) statusView() string {
	twoFA := "off"
	if m.ks.WrappedTOTPSeed != nil {
		twoFA = "on"
	}
	return "mode: " + string(m.ks.Mode) +
		"\n2fa: " + twoFA +
		"\nkeystore: " + m.deps.Store.Path() +
		"\nversion: " + m.deps.Version
}

func (m *Home) View() string {
	var b strings.Builder
	switch m.screen {
	case homeMenu:
		b.WriteString(m.menu.View())
		b.WriteString("\n" + m.th.dim.Render("enter select • / filter • q quit • esc quit"))
	case homePicker:
		return m.picker.View()
	case homeSecret:
		return m.prompt.View()
	case homeStatus:
		b.WriteString(m.th.title.Render("Status") + "\n\n" + m.statusText + "\n")
		b.WriteString("\n" + m.th.dim.Render("any key back"))
	case homeSettings:
		b.WriteString(m.settingsForm.View())
	case homeHelp:
		b.WriteString(m.th.title.Render("Keys") + "\n\n" + helpText + "\n")
		b.WriteString("\n" + m.th.dim.Render("any key back"))
	case homeResult:
		if m.resultIsErr {
			b.WriteString(m.th.errS.Render(m.result) + "\n")
		} else {
			b.WriteString(m.th.ok.Render(m.result) + "\n")
		}
		b.WriteString("\n" + m.th.dim.Render("any key back"))
	}
	return fit(b.String(), m.width, m.height)
}

// secretPrompt asks for the secret (and TOTP code for 2FA modes) without echo,
// PRD 5 and 8.2.
type secretPrompt struct {
	deps   *Deps
	ks     *keystore.Keystore
	action string
	pw     textinput.Model
	totp   textinput.Model
	focus  int
	errMsg string
	th     theme
	width  int
	height int
}

func newSecretPrompt(d *Deps, ks *keystore.Keystore, action string) *secretPrompt {
	th := newTheme(os.Stdout)
	pw := textinput.New()
	pw.EchoMode = textinput.EchoPassword
	pw.Placeholder = "Secret"
	pw.Focus()
	totp := textinput.New()
	totp.Placeholder = "6-digit code"
	return &secretPrompt{
		deps: d, ks: ks, action: action,
		pw: pw, totp: totp,
		th: th, width: maxWidth, height: maxHeight,
	}
}

func (p *secretPrompt) Init() tea.Cmd { return nil }

func (p *secretPrompt) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	k, ok := msg.(tea.KeyMsg)
	if !ok {
		return p.updateInputs(msg)
	}
	switch k.Type {
	case tea.KeyEsc:
		return p, func() tea.Msg { return promptCancelledMsg{} }
	case tea.KeyCtrlC:
		return p, tea.Quit
	case tea.KeyTab, tea.KeyShiftTab:
		if p.focus == 0 {
			p.focus = 1
			p.pw.Blur()
			return p, p.totp.Focus()
		}
		p.focus = 0
		p.totp.Blur()
		return p, p.pw.Focus()
	case tea.KeyEnter:
		if p.ks.Mode.Has2FA() && p.focus == 0 {
			p.focus = 1
			p.pw.Blur()
			return p, p.totp.Focus()
		}
		id, step, err := auth.NewAuthenticator(p.deps.KDF, p.deps.Wrapper, p.deps.DevStore, p.deps.TOTP).
			Authenticate(p.ks, []byte(p.pw.Value()), p.totp.Value())
		if err != nil {
			p.errMsg = "authentication failed; check the secret and the 2FA code"
			return p, nil
		}
		action := p.action
		return p, func() tea.Msg { return promptDoneMsg{action: action, identity: id, newStep: step} }
	}
	return p.updateInputs(msg)
}

func (p *secretPrompt) updateInputs(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	if p.focus == 0 || !p.ks.Mode.Has2FA() {
		p.pw, cmd = p.pw.Update(msg)
	} else {
		p.totp, cmd = p.totp.Update(msg)
	}
	return p, cmd
}

func (p *secretPrompt) View() string {
	var b strings.Builder
	b.WriteString(p.th.title.Render("Authenticate"))
	b.WriteString("\n\nSecret: " + p.pw.View() + "\n")
	if p.ks.Mode.Has2FA() {
		b.WriteString("2FA code: " + p.totp.View() + "\n")
	}
	if p.errMsg != "" {
		b.WriteString("\n" + p.th.errS.Render(p.errMsg) + "\n")
	}
	b.WriteString("\n" + p.th.dim.Render("enter confirm • tab next field • esc back"))
	return fit(b.String(), p.width, p.height)
}
