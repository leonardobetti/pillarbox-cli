package tui

import (
	"bytes"
	"errors"
	"os"
	"strings"

	"filippo.io/age"
	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"
	"github.com/mdp/qrterminal/v3"
	"rsc.io/qr"

	"github.com/leonardobetti/pillarbox-cli/internal/auth"
	"github.com/leonardobetti/pillarbox-cli/internal/keystore"
)

type screen int

const (
	screenWelcome screen = iota
	screenMode
	screenSecret
	screen2FA
	screenGate
	screenRecovery
)

type modeItem string

func (m modeItem) FilterValue() string { return string(m) }
func (m modeItem) Title() string       { return string(m) }
func (m modeItem) Description() string { return "" }

// Onboarding is the first-run flow of PRD 8.1 as a screen state machine:
// welcome, unlock mode, secret, 2FA setup (2FA modes), gate-encrypt question
// (2FA modes), recovery key. Nothing is written until the last screen
// completes, so Esc at any earlier screen leaves no keystore.
type Onboarding struct {
	deps *Deps
	th   theme

	screen     screen
	width      int
	height     int
	modeList   list.Model
	mode       keystore.Mode
	secret     textinput.Model
	confirm    textinput.Model
	focusField int

	codeInput textinput.Model
	seed      []byte
	uri       string
	qr        string // rendered QR code of the URI, terminal half-blocks
	copied    string // clipboard status line on the 2FA screen

	gateForm *huh.Form
	gateVal  bool

	savedForm *huh.Form
	savedVal  string

	identity *age.X25519Identity
	errMsg   string
	done     bool
}

func NewOnboarding(d *Deps) *Onboarding {
	th := newTheme(os.Stdout)
	modes := []list.Item{
		modeItem(keystore.ModePassword),
		modeItem(keystore.ModePIN),
		modeItem(keystore.ModePassword2FA),
		modeItem(keystore.ModePIN2FA),
	}
	del := list.NewDefaultDelegate()
	del.ShowDescription = false
	l := list.New(modes, del, maxWidth, 8)
	l.Title = "Unlock mode"
	l.SetShowHelp(false)
	l.SetShowStatusBar(false)
	l.SetShowPagination(false)

	pw := textinput.New()
	pw.EchoMode = textinput.EchoPassword
	pw.Placeholder = "Secret"
	pw.Focus()
	cf := textinput.New()
	cf.EchoMode = textinput.EchoPassword
	cf.Placeholder = "Confirm secret"

	code := textinput.New()
	code.Placeholder = "6-digit code"

	return &Onboarding{
		deps: d, th: th,
		width: maxWidth, height: maxHeight,
		modeList: l,
		secret:   pw, confirm: cf,
		codeInput: code,
	}
}

func (m *Onboarding) Init() tea.Cmd { return nil }

func (m *Onboarding) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.modeList.SetSize(msg.Width, msg.Height-10)
		if m.gateForm != nil {
			m.gateForm.Update(msg)
		}
		if m.savedForm != nil {
			m.savedForm.Update(msg)
		}
		return m, nil
	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyCtrlC:
			// On the 2FA screen Ctrl+C copies the URI to the clipboard
			// instead of aborting, so the QR payload can be pasted into an
			// authenticator app that cannot scan.
			if m.screen == screen2FA {
				m.copied = copyToClipboard(m.deps, m.uri)
				return m, nil
			}
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
		if k, ok := msg.(tea.KeyMsg); ok && (k.Type == tea.KeyEnter || k.Type == tea.KeySpace) {
			m.screen = screenMode
		}
	case screenMode:
		var cmd tea.Cmd
		m.modeList, cmd = m.modeList.Update(msg)
		if k, ok := msg.(tea.KeyMsg); ok && k.Type == tea.KeyEnter {
			if it, ok := m.modeList.SelectedItem().(modeItem); ok {
				m.mode = keystore.Mode(it)
				m.screen = screenSecret
				return m, m.secret.Focus()
			}
		}
		return m, cmd
	case screenSecret:
		return m.updateSecret(msg)
	case screen2FA:
		return m.update2FA(msg)
	case screenGate:
		return m.updateGate(msg)
	case screenRecovery:
		return m.updateRecovery(msg)
	}
	return m, nil
}

func (m *Onboarding) updateSecret(msg tea.Msg) (tea.Model, tea.Cmd) {
	k, ok := msg.(tea.KeyMsg)
	if !ok {
		return m.updateInputs(msg)
	}
	switch k.Type {
	case tea.KeyTab, tea.KeyShiftTab:
		if m.focusField == 0 {
			m.focusField = 1
			m.secret.Blur()
			return m, m.confirm.Focus()
		}
		m.focusField = 0
		m.confirm.Blur()
		return m, m.secret.Focus()
	case tea.KeyEnter:
		if m.focusField == 0 {
			m.focusField = 1
			m.secret.Blur()
			return m, m.confirm.Focus()
		}
		s, c := m.secret.Value(), m.confirm.Value()
		if s == "" || s != c {
			m.errMsg = "secrets do not match"
			return m, nil
		}
		if err := auth.ValidateSecret(m.mode, []byte(s)); err != nil {
			m.errMsg = "invalid secret: " + err.Error()
			return m, nil
		}
		m.errMsg = ""
		if m.mode.Has2FA() {
			seed, uri, err := m.deps.TOTP.GenerateSeed()
			if err != nil {
				m.errMsg = "cannot generate 2FA seed"
				return m, nil
			}
			m.seed, m.uri = seed, uri
			m.qr = renderQR(uri)
			m.copied = ""
			m.screen = screen2FA
			return m, m.codeInput.Focus()
		}
		return m, m.enterRecovery()
	}
	return m.updateInputs(msg)
}

func (m *Onboarding) updateInputs(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	if m.focusField == 0 {
		m.secret, cmd = m.secret.Update(msg)
	} else {
		m.confirm, cmd = m.confirm.Update(msg)
	}
	return m, cmd
}

func (m *Onboarding) update2FA(msg tea.Msg) (tea.Model, tea.Cmd) {
	if k, ok := msg.(tea.KeyMsg); ok && k.Type == tea.KeyEnter {
		ok, _, err := m.deps.TOTP.Verify(m.seed, m.codeInput.Value(), -1)
		if err != nil || !ok {
			m.errMsg = "invalid 2FA code"
			return m, nil
		}
		m.errMsg = ""
		m.screen = screenGate
		m.gateVal = false
		m.gateForm = huh.NewForm(huh.NewGroup(
			huh.NewConfirm().
				Title("Require 2FA to encrypt too?").
				Affirmative("Yes").Negative("No").
				Value(&m.gateVal),
		))
		return m, m.gateForm.Init()
	}
	var cmd tea.Cmd
	m.codeInput, cmd = m.codeInput.Update(msg)
	return m, cmd
}

func (m *Onboarding) updateGate(msg tea.Msg) (tea.Model, tea.Cmd) {
	updated, cmd := m.gateForm.Update(msg)
	if f, ok := updated.(*huh.Form); ok {
		m.gateForm = f
	}
	if m.gateForm.State == huh.StateCompleted {
		return m, m.enterRecovery()
	}
	return m, cmd
}

func (m *Onboarding) enterRecovery() tea.Cmd {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		m.errMsg = "cannot generate identity"
		return nil
	}
	m.identity = id
	m.screen = screenRecovery
	m.savedVal = ""
	m.savedForm = huh.NewForm(huh.NewGroup(
		huh.NewInput().
			Title("Recovery key shown above. Type 'saved' to continue").
			Value(&m.savedVal).
			Validate(func(s string) error {
				if s != "saved" {
					return errors.New("type saved to continue")
				}
				return nil
			}),
	))
	return m.savedForm.Init()
}

func (m *Onboarding) updateRecovery(msg tea.Msg) (tea.Model, tea.Cmd) {
	updated, cmd := m.savedForm.Update(msg)
	if f, ok := updated.(*huh.Form); ok {
		m.savedForm = f
	}
	if m.savedForm.State == huh.StateCompleted {
		return m, m.finalize()
	}
	return m, cmd
}

// finalize writes the keystore exactly once, PRD 8.1, then quits.
func (m *Onboarding) finalize() tea.Cmd {
	var devSecret []byte
	if m.mode.HasDeviceSecret() {
		var err error
		devSecret, _, err = m.deps.DevStore.LoadOrCreate()
		if err != nil {
			m.errMsg = "cannot write device secret"
			return nil
		}
	}
	ks, err := auth.NewInitializer(m.deps.KDF, m.deps.Wrapper).Initialize(
		m.mode, m.identity.Recipient().String(), []byte(m.identity.String()),
		[]byte(m.secret.Value()), devSecret, m.seed, keystore.DefaultArgon2Params)
	if err != nil {
		m.errMsg = "cannot build keystore"
		return nil
	}
	if err := m.deps.Store.Save(ks); err != nil {
		m.errMsg = "cannot write keystore"
		return nil
	}
	m.done = true
	return tea.Quit
}

func (m *Onboarding) View() string {
	var b strings.Builder
	switch m.screen {
	case screenWelcome:
		b.WriteString(m.th.title.Render("Welcome to Pillarbox"))
		b.WriteString("\n\nEncrypt and decrypt files and folders from the terminal.\n\n")
		b.WriteString("Commands to know: lock <path>, unlock <file.pbx>\n\n")
		b.WriteString(m.th.dim.Render("Press enter to continue"))
	case screenMode:
		b.WriteString(m.th.title.Render("Choose an unlock mode"))
		b.WriteString("\n\n")
		b.WriteString(m.modeList.View())
		b.WriteString("\n")
		b.WriteString(m.th.dim.Render("password: passphrase 12+ chars\npin: 6-12 digits, decrypts only on this device\npassword+2fa, pin+2fa: plus a TOTP code"))
	case screenSecret:
		b.WriteString(m.th.title.Render("Secret (" + string(m.mode) + ")"))
		b.WriteString("\n\nSecret: " + m.secret.View() + "\n")
		b.WriteString("Confirm: " + m.confirm.View() + "\n")
	case screen2FA:
		b.WriteString(m.th.title.Render("Set up 2FA"))
		b.WriteString("\n\nScan with your authenticator app, or ctrl+c to copy the URI:\n")
		b.WriteString(m.qr + "\n")
		b.WriteString(m.th.dim.Render(m.uri) + "\n\n")
		b.WriteString("Enter one valid code: " + m.codeInput.View() + "\n")
		if m.copied != "" {
			b.WriteString(m.th.ok.Render(m.copied) + "\n")
		}
	case screenGate:
		if m.gateForm != nil {
			b.WriteString(m.gateForm.View())
		}
	case screenRecovery:
		b.WriteString(m.th.title.Render("Recovery key"))
		if m.identity != nil {
			b.WriteString("\n\n" + m.th.ok.Render(m.identity.String()) + "\n")
		}
		b.WriteString(m.th.dim.Render("Save it now; it is shown only once.\n\n"))
		if m.savedForm != nil {
			b.WriteString(m.savedForm.View())
		}
	}
	if m.errMsg != "" {
		b.WriteString("\n" + m.th.errS.Render(m.errMsg) + "\n")
	}
	footer := "enter continue • tab next field • esc back • ctrl+c abort"
	if m.screen == screen2FA {
		footer = "enter continue • esc back • ctrl+c copy 2fa uri"
	}
	b.WriteString("\n" + m.th.dim.Render(footer))
	return fit(b.String(), m.width, m.height)
}

// renderQR renders the otpauth URI as a terminal QR code using half-block
// glyphs, so it stays scannable with NO_COLOR and on any background.
func renderQR(uri string) string {
	var buf bytes.Buffer
	qrterminal.GenerateWithConfig(uri, qrterminal.Config{
		Level:          qr.L,
		Writer:         &buf,
		HalfBlocks:     true,
		BlackChar:      "█",
		WhiteChar:      " ",
		BlackWhiteChar: "▀",
		WhiteBlackChar: "▄",
		QuietZone:      1,
	})
	return buf.String()
}

// copyToClipboard writes text through Deps.CopyText and reports the outcome
// in one line. A missing clipboard utility is a message, not a crash.
func copyToClipboard(d *Deps, text string) string {
	fn := d.CopyText
	if fn == nil {
		return "clipboard unavailable"
	}
	if err := fn(text); err != nil {
		return "clipboard unavailable"
	}
	return "copied 2FA URI to clipboard"
}
