package tui

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
	homePicker homeScreen = iota
	homeChooser
	homeSecret
	home2FA
	homeSettings
	homeStatus
	homeHelp
	homeResult
)

const (
	tabEncrypt = iota
	tabDecrypt
	tabStatus
	tabSettings
	tabHelp
)

var homeTabs = []string{"Encrypt", "Decrypt", "Status", "Settings", "Help"}

const tagline = "Pillarbox encrypts and decrypts files from the terminal."

const footerKeys = "Tab, ← or → to navigate  Enter to select  Q to quit  Backspace to change"

const helpIntro = "Pillarbox encrypts and decrypts files in the terminal. Your secret is stretched with Argon2id before the file is sealed with age. Free and open source, built by Leonardo Betti and Nasser Khalil with help from LLMs."

const helpText = "Tab / ← / → switch tabs • ↑/↓ move in the box • enter select • backspace toggle setting or parent dir • a apply (settings) • q quit • ctrl+c abort"

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

type modeItem string

func (m modeItem) FilterValue() string { return string(m) }
func (m modeItem) Title() string       { return string(m) }
func (m modeItem) Description() string { return "" }

// Home is the home shell: horizontal tabs, a bordered content box, and a
// keybinding footer. Every file is encrypted with its own key; the key type
// comes from Settings and is asked for when unset.
type Home struct {
	deps   *Deps
	th     theme
	screen homeScreen
	tab    int

	width, height int

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

func NewHome(d *Deps) *Home {
	th := newTheme(os.Stdout)

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

	h := &Home{
		deps:    d,
		th:      th,
		screen:  homePicker,
		tab:     tabEncrypt,
		width:   0,
		height:  0,
		chooser: cl,
	}
	h.reloadSettings()
	h.activateTab()
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

// tooSmall is true once the terminal has reported a size below the 800×800px
// cell budget. Width/height 0 means "not yet known" and is not treated as small.
func (m *Home) tooSmall() bool {
	if m.width <= 0 || m.height <= 0 {
		return false
	}
	return m.width < minTermWidth || m.height < minTermHeight
}

func (m *Home) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		innerW, innerH := m.contentSize()
		m.chooser.SetSize(innerW, max(innerH-2, 4))
		if m.picker != nil {
			m.picker.width, m.picker.height = innerW, innerH
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
		m.returnToTab()
		return m, nil
	case tea.KeyMsg:
		if msg.Type == tea.KeyCtrlC {
			// On the 2FA screen Ctrl+C copies the URI instead of quitting.
			if !m.tooSmall() && m.screen == home2FA {
				up, cmd := m.twofa.Update(msg)
				if p, ok := up.(*twofaPrompt); ok {
					m.twofa = p
				}
				return m, cmd
			}
			return m, tea.Quit
		}
		if msg.String() == "q" && !m.typing() {
			return m, tea.Quit
		}
		if m.tooSmall() {
			return m, nil
		}
		// Tab / arrows switch the top menu unless a text field is focused
		// or Settings is using arrows to toggle options.
		if m.canSwitchTab(msg) {
			return m.switchTab(msg)
		}
		if msg.Type == tea.KeyEsc {
			// Top-level tabs stay put; Q quits. Nested screens return to the tab.
			switch m.screen {
			case homePicker, homeStatus, homeHelp, homeSettings:
				return m, nil
			default:
				m.returnToTab()
				return m, nil
			}
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
					// Persist the choice so Settings keeps it between sessions.
					m.settings.KeyType = m.pendingMode
					if err := m.deps.Settings.Save(m.settings); err != nil {
						m.settingsErr = "cannot write settings"
					}
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
			m.returnToTab()
			return m, nil
		}
	}
	return m, nil
}

func (m *Home) typing() bool {
	if m.screen == homeSecret || m.screen == home2FA {
		return true
	}
	return m.screen == homePicker && m.picker != nil && m.picker.filtering
}

func (m *Home) canSwitchTab(msg tea.KeyMsg) bool {
	if m.typing() {
		return false
	}
	switch msg.Type {
	case tea.KeyTab, tea.KeyShiftTab:
		// Tab always moves the top menu, including leaving Settings → Help.
		return true
	case tea.KeyLeft, tea.KeyRight:
		// Chooser keeps ←/→ for its list; elsewhere they switch tabs.
		return m.screen != homeChooser
	}
	return false
}

func (m *Home) switchTab(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	n := len(homeTabs)
	switch msg.Type {
	case tea.KeyTab, tea.KeyRight:
		m.tab = (m.tab + 1) % n
	case tea.KeyShiftTab, tea.KeyLeft:
		m.tab = (m.tab - 1 + n) % n
	}
	m.activateTab()
	return m, nil
}

func (m *Home) activateTab() {
	m.pendingSecret = ""
	m.pendingPath = ""
	m.pendingKS = nil
	switch m.tab {
	case tabEncrypt:
		// With "require authentication to encrypt" on, the secret is asked
		// before the file picker and reused for the file's key.
		if m.settings.AuthEncrypt && m.settings.KeyType.Valid() {
			m.startSecret(m.settings.KeyType, "gate")
			break
		}
		m.openPicker("encrypt", "Select a file to encrypt")
	case tabDecrypt:
		m.openPicker("decrypt", "Select a .pbx file to decrypt")
	case tabStatus:
		m.statusText = m.statusView()
		m.screen = homeStatus
		m.picker = nil
	case tabSettings:
		m.reloadSettings()
		m.setCursor = 0
		m.screen = homeSettings
		m.picker = nil
	case tabHelp:
		m.screen = homeHelp
		m.picker = nil
	}
}

func (m *Home) returnToTab() {
	// Re-enter the active tab's default content. Clears pending encrypt state.
	m.pendingSecret = ""
	m.pendingPath = ""
	m.pendingKS = nil
	m.activateTab()
}

// updateSettings: ↑/↓ move the cursor, backspace toggles the current option,
// a applies. Tab/←/→ are handled by canSwitchTab so they leave for Help/etc.
func (m *Home) updateSettings(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	const n = 2
	switch msg.String() {
	case "up", "k":
		m.setCursor = (m.setCursor - 1 + n) % n
	case "down", "j":
		m.setCursor = (m.setCursor + 1) % n
	case "backspace", " ", "enter":
		m.toggleSetting(m.setCursor)
	case "a":
		if err := m.deps.Settings.Save(m.settings); err != nil {
			m.setResult("", err)
			return m, nil
		}
		m.returnToTab()
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
		m.settings.AuthEncrypt = !m.settings.AuthEncrypt
	}
}

func (m *Home) openPicker(action, title string) {
	m.picker = NewPicker(title, action, m.deps.StartDir, m.th)
	innerW, innerH := m.contentSize()
	m.picker.width, m.picker.height = innerW, innerH
	m.screen = homePicker
}

func (m *Home) runPicked(msg pickedMsg) {
	switch msg.action {
	case "encrypt":
		m.pendingPath = msg.path
		if m.pendingSecret != "" {
			// Secret already collected at the auth gate.
			m.startEncryptWithSecret(m.pendingMode, m.pendingSecret)
			return
		}
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
		ks, err := m.deps.Vault.ReadKey(msg.path)
		if err != nil {
			m.setResult("", errors.New("no key for this file or key invalid"))
			return
		}
		m.pendingPath = msg.path
		m.pendingKS = ks
		m.startSecret(ks.Mode, "decrypt")
	}
}

func (m *Home) startSecret(mode keystore.Mode, action string) {
	m.pendingMode = mode
	file := ""
	if action == "decrypt" {
		file = m.pendingPath
	}
	m.prompt = newSecretPrompt(m.deps, mode, action, file)
	m.screen = homeSecret
}

func (m *Home) runPromptDone(msg promptDoneMsg) {
	if msg.action == "gate" {
		// Auth gate passed: keep the secret and go pick the file.
		m.pendingMode = msg.mode
		m.pendingSecret = msg.secret
		m.openPicker("encrypt", "Select a file to encrypt")
		return
	}
	if msg.action == "encrypt" {
		m.startEncryptWithSecret(msg.mode, msg.secret)
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
		_ = m.deps.Vault.SaveKey(m.pendingPath, m.pendingKS)
	}
	identity, err := age.ParseX25519Identity(string(id))
	if err != nil {
		m.setResult("", err)
		return
	}
	// The TUI overwrites the original when it still exists next to the .pbx.
	dst, err := m.deps.Vault.Unlock(m.pendingPath, identity, vault.UnlockOptions{Force: true})
	if err != nil {
		m.setResult("", err)
		return
	}
	m.setResult(keystore.FormatDecryptSuccess(dst), nil)
}

// startEncryptWithSecret runs the encrypt flow with an already collected
// secret: the 2FA QR screen for 2FA modes, otherwise the lock right away.
func (m *Home) startEncryptWithSecret(mode keystore.Mode, secret string) {
	m.pendingMode = mode
	m.pendingSecret = secret
	if mode.Has2FA() {
		seed, uri, err := m.deps.TOTP.GenerateSeed()
		if err != nil {
			m.setResult("", errors.New("cannot generate 2FA seed"))
			return
		}
		m.twofa = newTwofaPrompt(m.deps, seed, uri)
		m.screen = home2FA
		return
	}
	m.doEncrypt(secret, nil)
}

func (m *Home) run2FADone(msg twofaDoneMsg) {
	secret := m.pendingSecret
	m.pendingSecret = ""
	m.doEncrypt(secret, msg.seed)
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
	locked, err := m.deps.Vault.Lock(m.pendingPath, ks, vault.LockOptions{})
	if err != nil {
		m.setResult("", err)
		return
	}
	m.pendingSecret = ""
	m.setResult(keystore.FormatEncryptSuccess(locked, mode, false, identity.String()), nil)
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
	return fmt.Sprintf("key type: %s\nauth-encrypt: %t\nsettings: %s\nversion: %s",
		keyType, m.settings.AuthEncrypt, m.deps.Settings.Path(), m.deps.Version)
}

// chromeLines is the fixed vertical cost of header + tabs + footer around the box.
const chromeLines = 9 // title, tagline, blank, tabs, tab underline, blank, box gap, footer gap, footer

func (m *Home) contentSize() (w, h int) {
	termW, termH := m.width, m.height
	if termW <= 0 {
		termW = minTermWidth
	}
	if termH <= 0 {
		termH = minTermHeight
	}
	w = termW - 4 // box borders + padding
	if w < 20 {
		w = 20
	}
	h = termH - chromeLines - 2 // box top/bottom borders
	if h < 4 {
		h = 4
	}
	return w, h
}

func (m *Home) resizeView() string {
	var b strings.Builder
	b.WriteString(m.th.title.Render("Pillarbox"))
	b.WriteString("\n\n")
	b.WriteString(m.th.dim.Render("Terminal too small for this UI."))
	b.WriteString("\n")
	fmt.Fprintf(&b, "Need at least %d×%d cells (~800×800px). Now %d×%d.",
		minTermWidth, minTermHeight, m.width, m.height)
	b.WriteString("\n\n")
	b.WriteString(m.th.dim.Render("Resize the window, or press q to quit."))
	w, h := m.width, m.height
	if w <= 0 {
		w = minTermWidth
	}
	if h <= 0 {
		h = minTermHeight
	}
	return fit(b.String(), w, h)
}

func (m *Home) View() string {
	if m.tooSmall() {
		return m.resizeView()
	}
	var b strings.Builder
	b.WriteString(m.th.title.Render("Pillarbox"))
	b.WriteString("\n")
	// Dense screens (2FA QR) drop the tagline so the code entry stays visible.
	if m.screen != home2FA {
		b.WriteString(m.th.dim.Render(tagline))
		b.WriteString("\n\n")
		b.WriteString(m.renderTabs())
		b.WriteString("\n\n")
	} else {
		b.WriteString("\n")
	}

	innerW, innerH := m.contentSize()
	if m.screen == home2FA {
		innerH = m.height - 5 // title + blanks + footer only
	}
	body := m.contentBody(innerH)
	// Cap the body to the box before styling so the border is drawn around a
	// known plain-text size. Do not set Height on the box: lipgloss pads with
	// blank cells that then fight ansi.Wrap in fit().
	body = clampLines(body, innerH)
	b.WriteString(m.th.box.Width(innerW).Render(body))
	b.WriteString("\n\n")
	b.WriteString(m.th.dim.Render(footerKeys))
	w, h := m.width, m.height
	if w <= 0 {
		w = minTermWidth
	}
	if h <= 0 {
		h = minTermHeight
	}
	return fit(b.String(), w, h)
}

// renderTabs draws the tab labels and a second line of ─ under the active tab.
// Underline is a separate row of characters, not SGR underline — that kept
// fit() from tearing the active label apart.
func (m *Home) renderTabs() string {
	var labels strings.Builder
	var under strings.Builder
	for i, name := range homeTabs {
		if i > 0 {
			labels.WriteString("  ")
			under.WriteString("  ")
		}
		if i == m.tab {
			labels.WriteString(m.th.tabActive.Render(name))
			under.WriteString(m.th.accent.Render(strings.Repeat("─", len([]rune(name)))))
		} else {
			labels.WriteString(m.th.tab.Render(name))
			under.WriteString(strings.Repeat(" ", len([]rune(name))))
		}
	}
	return labels.String() + "\n" + under.String()
}

func clampLines(s string, max int) string {
	if max <= 0 {
		return s
	}
	lines := strings.Split(s, "\n")
	if len(lines) > max {
		lines = lines[:max]
	}
	return strings.Join(lines, "\n")
}

func (m *Home) contentBody(innerH int) string {
	switch m.screen {
	case homePicker:
		if m.picker == nil {
			return ""
		}
		return m.picker.ContentView(innerH)
	case homeChooser:
		var b strings.Builder
		b.WriteString("Key type not set in Settings\n\n")
		b.WriteString(m.chooser.View())
		return b.String()
	case homeSecret:
		return m.prompt.ContentView()
	case home2FA:
		return m.twofa.ContentView()
	case homeSettings:
		keyType := string(m.settings.KeyType)
		if keyType == "" {
			keyType = "(not set)"
		}
		auth := "no"
		if m.settings.AuthEncrypt {
			auth = "yes"
		}
		var b strings.Builder
		b.WriteString("Settings\n\n")
		for i, line := range []string{"Key type: " + keyType, "Require authentication to encrypt: " + auth} {
			marker := "  "
			if i == m.setCursor {
				marker = "> "
			}
			b.WriteString(marker + line + "\n")
		}
		b.WriteString("\n" + m.th.dim.Render("↑/↓ move • backspace toggle • a apply • tab next section"))
		return b.String()
	case homeStatus:
		return "Status\n\n" + m.statusText
	case homeHelp:
		return "Help\n\n" + helpIntro + "\n\n" + helpText
	case homeResult:
		if m.resultIsErr {
			return m.th.errS.Render(m.result)
		}
		return m.th.ok.Render(m.result)
	}
	return ""
}

// secretPrompt collects the secret for one operation, with the mode's rules
// shown above the input. For 2FA modes a second field takes the TOTP code.
type secretPrompt struct {
	deps   *Deps
	th     theme
	mode   keystore.Mode
	action string
	file   string // basename of the .pbx when decrypting; empty otherwise
	pw     textinput.Model
	code   textinput.Model
	focus  int
	errMsg string
}

func newSecretPrompt(d *Deps, mode keystore.Mode, action, file string) *secretPrompt {
	th := newTheme(os.Stdout)
	pw := textinput.New()
	pw.EchoMode = textinput.EchoPassword
	if mode.HasDeviceSecret() {
		pw.Placeholder = "PIN"
	} else {
		pw.Placeholder = "Passphrase"
	}
	pw.Focus()
	code := textinput.New()
	code.Placeholder = "6-digit 2FA code"
	return &secretPrompt{
		deps: d, th: th, mode: mode, action: action,
		file: filepath.Base(file), pw: pw, code: code,
	}
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

func (p *secretPrompt) ContentView() string {
	var b strings.Builder
	if p.action == "decrypt" {
		if p.file != "" {
			b.WriteString(p.file + "\n")
		}
		b.WriteString(p.th.accent.Render(p.mode.NeedsSummary()) + "\n\n")
	} else {
		b.WriteString("Secret (" + string(p.mode) + ")\n\n")
	}
	for _, rule := range auth.SecretRules(p.mode) {
		b.WriteString(p.th.dim.Render(rule) + "\n")
	}
	label := "Passphrase: "
	if p.mode.HasDeviceSecret() {
		label = "PIN: "
	}
	b.WriteString("\n" + label + p.pw.View() + "\n")
	if p.mode.Has2FA() && p.action == "decrypt" {
		b.WriteString("2FA code: " + p.code.View() + "\n")
	}
	if p.errMsg != "" {
		b.WriteString("\n" + p.th.errS.Render(p.errMsg) + "\n")
	}
	return strings.TrimRight(b.String(), "\n")
}

func (p *secretPrompt) View() string {
	return fit(p.ContentView()+"\n\n"+p.th.dim.Render("tab next field • enter continue • esc back • ctrl+c abort"), maxWidth, maxHeight)
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

func (p *twofaPrompt) ContentView() string {
	// Side-by-side QR + code entry so the input survives the 24-line budget.
	var b strings.Builder
	b.WriteString("Set up 2FA for this file\n")
	qrLines := strings.Split(strings.TrimRight(p.qr, "\n"), "\n")
	side := []string{
		"Scan the QR, or ctrl+c copies the URI.",
		"",
		"Enter the 6-digit code:",
		p.code.View(),
	}
	if p.copied != "" {
		side = append(side, p.th.ok.Render(p.copied))
	}
	if p.errMsg != "" {
		side = append(side, p.th.errS.Render(p.errMsg))
	}
	for i, ql := range qrLines {
		line := ql
		if i < len(side) {
			line += "  " + side[i]
		}
		b.WriteString(line + "\n")
	}
	for i := len(qrLines); i < len(side); i++ {
		b.WriteString(side[i] + "\n")
	}
	return strings.TrimRight(b.String(), "\n")
}

func (p *twofaPrompt) View() string {
	return fit(p.ContentView()+"\n\n"+p.th.dim.Render("enter continue • esc back • ctrl+c copy 2fa uri"), maxWidth, maxHeight)
}
