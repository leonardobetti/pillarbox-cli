package tui

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"filippo.io/age"
	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/leonardobetti/pillarbox-cli/internal/auth"
	"github.com/leonardobetti/pillarbox-cli/internal/keystore"
	"github.com/leonardobetti/pillarbox-cli/internal/vault"
)

type homeScreen int

const (
	homeMenu homeScreen = iota
	homePicker
	homeChooser
	homeSecret
	home2FA
	homeSettings
	homeStatus
	homeHelp
	homeResult
)

type menuItem string

func (m menuItem) FilterValue() string { return string(m) }
func (m menuItem) Title() string       { return string(m) }
func (m menuItem) Description() string { return "" }

type promptDoneMsg struct {
	action string
	mode   keystore.Mode
	secret string
	code   string
}

type twofaDoneMsg struct {
	seed []byte
}

type promptCancelledMsg struct{}

// Home is the home menu: Encrypt, Decrypt, Status, Settings, Help. Every file
// is encrypted with its own key; the key type comes from Settings and is
// asked for when unset.
type Home struct {
	deps   *Deps
	th     theme
	screen homeScreen

	width, height int
	menu          list.Model

	settings    *keystore.Settings
	settingsErr string

	picker  *Picker
	chooser list.Model
	prompt  *secretPrompt
	twofa   *twofaPrompt

	pendingPath   string             // file picked in the picker
	pendingKS     *keystore.Keystore // sidecar loaded for decrypt
	pendingMode   keystore.Mode
	pendingSecret string

	setCursor int

	statusText  string
	result      string
	resultIsErr bool
}

const helpText = "↑/↓ or tab navigate • backspace toggle switch • a apply • enter select • esc back • q quit • ctrl+c abort"

func NewHome(d *Deps) *Home {
	th := newTheme(os.Stdout)
	items := []list.Item{
		menuItem("Encrypt"),
		menuItem("Decrypt"),
		menuItem("Status"),
		menuItem("Settings"),
		menuItem("Help"),
	}
	l := list.New(items, list.NewDefaultDelegate(), maxWidth, 8)
	l.Title = "Pillarbox"
	l.SetShowHelp(false)
	l.SetShowStatusBar(false)
	l.SetShowPagination(false)
	l.SetFilteringEnabled(false)

	modes := []list.Item{
		modeItem(keystore.ModePassword),
		modeItem(keystore.ModePIN),
		modeItem(keystore.ModePassword2FA),
		modeItem(keystore.ModePIN2FA),
	}
	cl := list.New(modes, list.NewDefaultDelegate(), maxWidth, 6)
	cl.Title = "Key type for this file"
	cl.SetShowHelp(false)
	cl.SetShowStatusBar(false)
	cl.SetShowPagination(false)
	cl.SetFilteringEnabled(false)

	h := &Home{deps: d, th: th, screen: homeMenu, width: maxWidth, height: maxHeight, menu: l, chooser: cl}
	h.reloadSettings()
	return h
}

func (m *Home) reloadSettings() {
	st, err := m.deps.Settings.Load()
	if err != nil {
		m.settings = &keystore.Settings{}
		m.settingsErr = "settings missing or invalid; run pillarbox to set up"
		return
	}
	m.settings = st
}

func (m *Home) Init() tea.Cmd { return nil }

func (m *Home) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.menu.SetSize(msg.Width, msg.Height-8)
		m.chooser.SetSize(msg.Width, msg.Height-10)
		if m.picker != nil {
			m.picker.width, m.picker.height = msg.Width, msg.Height
		}
		return m, nil
	case pickedMsg:
		m.runPicked(msg)
		return m, nil
	case promptDoneMsg:
		m.runPromptDone(msg)
		return m, nil
	case twofaDoneMsg:
		m.run2FADone(msg)
		return m, nil
	case promptCancelledMsg, pickerCancelledMsg:
		m.screen = homeMenu
		return m, nil
	case tea.KeyMsg:
		if msg.Type == tea.KeyCtrlC {
			// On the 2FA screen Ctrl+C copies the URI instead of quitting.
			if m.screen == home2FA {
				up, cmd := m.twofa.Update(msg)
				if p, ok := up.(*twofaPrompt); ok {
					m.twofa = p
				}
				return m, cmd
			}
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
		case homeChooser:
			var cmd tea.Cmd
			m.chooser, cmd = m.chooser.Update(msg)
			if msg.Type == tea.KeyEnter {
				if it, ok := m.chooser.SelectedItem().(modeItem); ok {
					m.pendingMode = keystore.Mode(it)
					m.startSecret(m.pendingMode, "encrypt")
				}
			}
			return m, cmd
		case homeSecret:
			up, cmd := m.prompt.Update(msg)
			if p, ok := up.(*secretPrompt); ok {
				m.prompt = p
			}
			return m, cmd
		case home2FA:
			up, cmd := m.twofa.Update(msg)
			if p, ok := up.(*twofaPrompt); ok {
				m.twofa = p
			}
			return m, cmd
		case homeSettings:
			return m.updateSettings(msg)
		case homeStatus, homeHelp, homeResult:
			if msg.String() == "q" {
				return m, tea.Quit
			}
			m.screen = homeMenu
			return m, nil
		}
	}
	return m, nil
}

func (m *Home) updateMenu(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	if msg.Type == tea.KeyTab || msg.Type == tea.KeyShiftTab {
		n := len(m.menu.Items())
		if n > 0 {
			i := m.menu.Index()
			if msg.Type == tea.KeyTab {
				m.menu.Select((i + 1) % n)
			} else {
				m.menu.Select((i - 1 + n) % n)
			}
		}
		return m, nil
	}
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
		m.openPicker("encrypt", "Encrypt — select a file")
	case "Decrypt":
		m.openPicker("decrypt", "Decrypt — select a .pbx file")
	case "Status":
		m.statusText = m.statusView()
		m.screen = homeStatus
	case "Settings":
		m.reloadSettings()
		m.setCursor = 0
		m.screen = homeSettings
	case "Help":
		m.screen = homeHelp
	}
	return m, cmd
}

// updateSettings is a stable option list: one keypress, one action, no loop.
// up/down/tab/backspace move the cursor, left/right flip the current option,
// a applies and persists, esc/q leave.
func (m *Home) updateSettings(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	const n = 2
	switch msg.String() {
	case "up", "shift+tab":
		m.setCursor = (m.setCursor - 1 + n) % n
	case "down", "tab", "backspace":
		m.setCursor = (m.setCursor + 1) % n
	case "left", "right", "h", "l", "space":
		m.toggleSetting(m.setCursor)
	case "a":
		if err := m.deps.Settings.Save(m.settings); err != nil {
			m.setResult("", err)
			return m, nil
		}
		m.screen = homeMenu
	case "q":
		return m, tea.Quit
	}
	return m, nil
}

func (m *Home) toggleSetting(i int) {
	if i == 0 {
		modes := []keystore.Mode{keystore.ModePassword, keystore.ModePIN, keystore.ModePassword2FA, keystore.ModePIN2FA}
		cur := 0
		for j, mm := range modes {
			if mm == m.settings.KeyType {
				cur = j
			}
		}
		m.settings.KeyType = modes[(cur+1)%len(modes)]
	} else {
		m.settings.GateEncrypt = !m.settings.GateEncrypt
	}
}

func (m *Home) openPicker(action, title string) {
	m.picker = NewPicker(title, action, m.deps.StartDir, m.th)
	m.screen = homePicker
}

func (m *Home) runPicked(msg pickedMsg) {
	switch msg.action {
	case "encrypt":
		m.pendingPath = msg.path
		if !m.settings.KeyType.Valid() {
			m.screen = homeChooser
			return
		}
		m.startSecret(m.settings.KeyType, "encrypt")
	case "decrypt":
		if !strings.HasSuffix(msg.path, ".pbx") {
			m.setResult("", errors.New("select a .pbx file"))
			return
		}
		ks, err := keystore.NewStore(msg.path + ".key").Load()
		if err != nil {
			m.setResult("", errors.New("no key for this file or key file invalid"))
			return
		}
		m.pendingPath = msg.path
		m.pendingKS = ks
		m.startSecret(ks.Mode, "decrypt")
	}
}

func (m *Home) startSecret(mode keystore.Mode, action string) {
	m.pendingMode = mode
	m.prompt = newSecretPrompt(m.deps, mode, action)
	m.screen = homeSecret
}

func (m *Home) runPromptDone(msg promptDoneMsg) {
	if msg.action == "encrypt" {
		if msg.mode.Has2FA() {
			seed, uri, err := m.deps.TOTP.GenerateSeed()
			if err != nil {
				m.setResult("", errors.New("cannot generate 2FA seed"))
				return
			}
			m.twofa = newTwofaPrompt(m.deps, seed, uri)
			m.pendingSecret = msg.secret
			m.screen = home2FA
			return
		}
		m.doEncrypt(msg.secret, nil)
		return
	}
	// decrypt
	id, step, err := auth.NewAuthenticator(m.deps.KDF, m.deps.Wrapper, m.deps.DevStore, m.deps.TOTP).
		Authenticate(m.pendingKS, []byte(msg.secret), msg.code)
	if err != nil {
		m.setResult("", errors.New("authentication failed; check the secret and the 2FA code"))
		return
	}
	if m.pendingKS.Mode.Has2FA() {
		m.pendingKS.LastTOTPStep = &step
		_ = keystore.NewStore(m.pendingPath + ".key").Save(m.pendingKS)
	}
	identity, err := age.ParseX25519Identity(string(id))
	if err != nil {
		m.setResult("", err)
		return
	}
	dst, err := m.deps.Vault.Unlock(m.pendingPath, identity, vault.UnlockOptions{})
	m.setResult(dst, err)
}

func (m *Home) run2FADone(msg twofaDoneMsg) {
	m.doEncrypt(m.pendingSecret, msg.seed)
}

func (m *Home) doEncrypt(secret string, seed []byte) {
	mode := m.pendingMode
	var devSecret []byte
	if mode.HasDeviceSecret() {
		var err error
		devSecret, _, err = m.deps.DevStore.LoadOrCreate()
		if err != nil {
			m.setResult("", errors.New("cannot write device secret"))
			return
		}
	}
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		m.setResult("", err)
		return
	}
	ks, err := auth.NewInitializer(m.deps.KDF, m.deps.Wrapper).Initialize(
		mode, identity.Recipient().String(), []byte(identity.String()),
		[]byte(secret), devSecret, seed, keystore.DefaultArgon2Params)
	if err != nil {
		m.setResult("", err)
		return
	}
	dst := m.pendingPath + ".pbx"
	locked, err := m.deps.Vault.Lock(m.pendingPath, ks.Recipient, vault.LockOptions{})
	if err != nil {
		m.setResult("", err)
		return
	}
	if err := keystore.NewStore(dst + ".key").Save(ks); err != nil {
		_ = os.Remove(locked)
		m.setResult("", errors.New("cannot write file key"))
		return
	}
	m.setResult(locked+"\nrecovery key (shown once): "+identity.String(), nil)
}

func (m *Home) setResult(dst string, err error) {
	if err != nil {
		m.result = err.Error()
		m.resultIsErr = true
	} else {
		m.result = dst
		m.resultIsErr = false
	}
	m.screen = homeResult
}

func (m *Home) statusView() string {
	keyType := string(m.settings.KeyType)
	if keyType == "" {
		keyType = "(not set)"
	}
	return fmt.Sprintf("key type: %s\ngate-encrypt: %t\nsettings: %s\nversion: %s",
		keyType, m.settings.GateEncrypt, m.deps.Settings.Path(), m.deps.Version)
}

func (m *Home) View() string {
	var b strings.Builder
	switch m.screen {
	case homeMenu:
		b.WriteString(m.menu.View())
		b.WriteString("\n" + m.th.dim.Render("↑/↓ or tab navigate • enter select • esc back • q quit • ctrl+c abort"))
	case homePicker:
		return m.picker.View()
	case homeChooser:
		b.WriteString(m.th.title.Render("Key type not set in Settings"))
		b.WriteString("\n\nChoose the key type for this file:\n\n")
		b.WriteString(m.chooser.View())
		b.WriteString("\n" + m.th.dim.Render("↑/↓ or tab navigate • enter select • esc back • q quit"))
	case homeSecret:
		return m.prompt.View()
	case home2FA:
		return m.twofa.View()
	case homeSettings:
		keyType := string(m.settings.KeyType)
		if keyType == "" {
			keyType = "(not set)"
		}
		gate := "no"
		if m.settings.GateEncrypt {
			gate = "yes"
		}
		b.WriteString(m.th.title.Render("Settings"))
		b.WriteString("\n\n")
		for i, line := range []string{"Key type: " + keyType, "Gate encrypt: " + gate} {
			marker := "  "
			if i == m.setCursor {
				marker = "> "
			}
			b.WriteString(marker + line + "\n")
		}
		b.WriteString("\n" + m.th.dim.Render("↑/↓/tab/backspace move • ←/→ toggle • a apply • esc back • q quit • ctrl+c abort"))
	case homeStatus:
		b.WriteString(m.th.title.Render("Status") + "\n\n" + m.statusText + "\n")
		b.WriteString("\n" + m.th.dim.Render("any key back • q quit"))
	case homeHelp:
		b.WriteString(m.th.title.Render("Keys") + "\n\n" + helpText + "\n")
		b.WriteString("\n" + m.th.dim.Render("any key back • q quit"))
	case homeResult:
		if m.resultIsErr {
			b.WriteString(m.th.errS.Render(m.result) + "\n")
		} else {
			b.WriteString(m.th.ok.Render(m.result) + "\n")
		}
		b.WriteString("\n" + m.th.dim.Render("any key back • q quit"))
	}
	return fit(b.String(), m.width, m.height)
}

// secretPrompt collects the secret for one operation, with the mode's rules
// shown above the input. For 2FA modes a second field takes the TOTP code.
type secretPrompt struct {
	deps   *Deps
	th     theme
	mode   keystore.Mode
	action string
	pw     textinput.Model
	code   textinput.Model
	focus  int
	errMsg string
}

func newSecretPrompt(d *Deps, mode keystore.Mode, action string) *secretPrompt {
	th := newTheme(os.Stdout)
	pw := textinput.New()
	pw.EchoMode = textinput.EchoPassword
	pw.Placeholder = "Secret"
	pw.Focus()
	code := textinput.New()
	code.Placeholder = "6-digit code"
	return &secretPrompt{deps: d, th: th, mode: mode, action: action, pw: pw, code: code}
}

func (p *secretPrompt) Init() tea.Cmd { return nil }

func (p *secretPrompt) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	k, ok := msg.(tea.KeyMsg)
	if !ok {
		return p.updateInputs(msg)
	}
	switch k.String() {
	case "tab", "shift+tab", "enter":
		// The 2FA code is only asked at decrypt; at encrypt the QR screen
		// verifies it against the fresh per-file seed.
		if p.mode.Has2FA() && p.action == "decrypt" && p.focus == 0 {
			p.focus = 1
			p.pw.Blur()
			return p, p.code.Focus()
		}
		secret := p.pw.Value()
		if err := auth.ValidateSecret(p.mode, []byte(secret)); err != nil {
			p.errMsg = "invalid secret: " + err.Error()
			return p, nil
		}
		if p.mode.Has2FA() && p.action == "decrypt" && p.code.Value() == "" {
			p.errMsg = "enter the 2FA code"
			return p, nil
		}
		return p, func() tea.Msg {
			return promptDoneMsg{action: p.action, mode: p.mode, secret: secret, code: p.code.Value()}
		}
	case "esc":
		return p, func() tea.Msg { return promptCancelledMsg{} }
	case "ctrl+c":
		return p, tea.Quit
	}
	return p.updateInputs(msg)
}

func (p *secretPrompt) updateInputs(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	if p.focus == 0 || !p.mode.Has2FA() || p.action != "decrypt" {
		p.pw, cmd = p.pw.Update(msg)
	} else {
		p.code, cmd = p.code.Update(msg)
	}
	return p, cmd
}

func (p *secretPrompt) View() string {
	var b strings.Builder
	b.WriteString(p.th.title.Render("Secret (" + string(p.mode) + ")"))
	b.WriteString("\n\n")
	for _, rule := range auth.SecretRules(p.mode) {
		b.WriteString(p.th.dim.Render(rule) + "\n")
	}
	b.WriteString("\nSecret: " + p.pw.View() + "\n")
	if p.mode.Has2FA() && p.action == "decrypt" {
		b.WriteString("2FA code: " + p.code.View() + "\n")
	}
	if p.errMsg != "" {
		b.WriteString("\n" + p.th.errS.Render(p.errMsg) + "\n")
	}
	b.WriteString("\n" + p.th.dim.Render("tab next field • enter continue • esc back • ctrl+c abort"))
	return fit(b.String(), maxWidth, maxHeight)
}

// twofaPrompt shows the QR code of the per-file TOTP seed and asks for one
// valid code. Ctrl+C copies the URI to the clipboard.
type twofaPrompt struct {
	deps   *Deps
	th     theme
	seed   []byte
	uri    string
	qr     string
	code   textinput.Model
	copied string
	errMsg string
}

func newTwofaPrompt(d *Deps, seed []byte, uri string) *twofaPrompt {
	th := newTheme(os.Stdout)
	code := textinput.New()
	code.Placeholder = "6-digit code"
	code.Focus()
	return &twofaPrompt{deps: d, th: th, seed: seed, uri: uri, qr: renderQR(uri), code: code}
}

func (p *twofaPrompt) Init() tea.Cmd { return nil }

func (p *twofaPrompt) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	k, ok := msg.(tea.KeyMsg)
	if !ok {
		var cmd tea.Cmd
		p.code, cmd = p.code.Update(msg)
		return p, cmd
	}
	switch k.String() {
	case "ctrl+c":
		p.copied = copyToClipboard(p.deps, p.uri)
		return p, nil
	case "esc":
		return p, func() tea.Msg { return promptCancelledMsg{} }
	case "enter":
		ok, _, err := p.deps.TOTP.Verify(p.seed, p.code.Value(), -1)
		if err != nil || !ok {
			p.errMsg = "invalid 2FA code"
			return p, nil
		}
		seed := p.seed
		return p, func() tea.Msg { return twofaDoneMsg{seed: seed} }
	}
	var cmd tea.Cmd
	p.code, cmd = p.code.Update(k)
	return p, cmd
}

func (p *twofaPrompt) View() string {
	var b strings.Builder
	b.WriteString(p.th.title.Render("Set up 2FA for this file"))
	b.WriteString("\n\nScan with your authenticator app, or ctrl+c to copy the URI:\n")
	b.WriteString(p.qr + "\n")
	b.WriteString(p.th.dim.Render(p.uri) + "\n\n")
	b.WriteString("Enter one valid code: " + p.code.View() + "\n")
	if p.copied != "" {
		b.WriteString(p.th.ok.Render(p.copied) + "\n")
	}
	if p.errMsg != "" {
		b.WriteString("\n" + p.th.errS.Render(p.errMsg) + "\n")
	}
	b.WriteString("\n" + p.th.dim.Render("enter continue • esc back • ctrl+c copy 2fa uri"))
	return fit(b.String(), maxWidth, maxHeight)
}
