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
	homeConfirmDecrypt
	homePostEncrypt
	homeThemePicker
	homeThemeConfirm
)

type postEncryptPhase int

const (
	postRecoveryAck postEncryptPhase = iota
	postKeepOriginal
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

const footerKeys = "{Tab}, {←} or {→} to navigate  {Enter} to select  {Q} to quit  {Backspace} to change"

const helpIntro = "Pillarbox encrypts and decrypts files in the terminal. Your secret is stretched with Argon2id before the file is sealed with age. Free and open source, built by Leonardo Betti and Nasser Khalil with help from LLMs."

const helpFAQ = `Settings set the default for NEW files only. Each .pbx stores its own mode and key.
2FA: one QR for this install. Every 2FA file shares that authenticator entry.
PIN files need this machine's device secret, or the recovery key.
Each encrypt shows a recovery key once. Save it.`

const helpText = "{Tab} / {←} / {→} switch tabs • {↑}/{↓} move in the box • {Enter} select • {Backspace} toggle setting or parent dir • {A} apply (settings) • {Q} quit • {Ctrl+C} abort"

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
func (m modeItem) Description() string {
	if keystore.Mode(m).Has2FA() {
		return "One QR for all 2FA files on this install"
	}
	return ""
}

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

	themeBefore  string // theme id to restore if the theme picker is cancelled
	themeFilter  string // live name filter in the theme picker
	themeCursor  int    // index into the filtered theme list
	themePending string // theme id waiting on the apply confirm screen

	pendingPath   string             // file picked in the picker
	pendingKS     *keystore.Keystore // sidecar loaded for decrypt
	pendingMode   keystore.Mode
	pendingSecret string

	pendingIdentity *age.X25519Identity // decrypt after overwrite confirm
	pendingOrigName string
	decryptDst      string

	postPhase    postEncryptPhase
	postLocked   string
	postOriginal string
	postMode     keystore.Mode
	postRecovery string

	defaultSavedNotice bool

	setCursor int

	statusText  string
	result      string
	resultIsErr bool
}

func NewHome(d *Deps) *Home {
	modes := []list.Item{
		modeItem(keystore.ModePassword),
		modeItem(keystore.ModePIN),
		modeItem(keystore.ModePassword2FA),
		modeItem(keystore.ModePIN2FA),
	}
	delegate := list.NewDefaultDelegate()
	delegate.SetHeight(2)
	delegate.SetSpacing(0)
	cl := list.New(modes, delegate, maxWidth, 10)
	cl.Title = "Default key type for new files"
	cl.SetShowHelp(false)
	cl.SetShowStatusBar(false)
	cl.SetShowPagination(false)
	cl.SetFilteringEnabled(false)

	h := &Home{
		deps:    d,
		screen:  homePicker,
		tab:     tabEncrypt,
		width:   0,
		height:  0,
		chooser: cl,
	}
	h.reloadSettings()
	h.applyTheme(h.settings.Theme)
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

func (m *Home) applyTheme(name string) {
	m.th = newTheme(os.Stdout, name)
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
			// Stay on the recovery-key screen until the user acknowledges it.
			if m.screen == homePostEncrypt && m.postPhase == postRecoveryAck {
				return m, nil
			}
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
			case homeThemePicker:
				if m.themeFilter != "" {
					m.themeFilter = ""
					m.clampThemeCursor()
					m.previewThemeAtCursor()
					return m, nil
				}
				m.cancelThemePicker()
				return m, nil
			case homeThemeConfirm:
				m.themePending = ""
				m.previewThemeAtCursor()
				m.screen = homeThemePicker
				return m, nil
			case homePostEncrypt:
				if m.postPhase == postRecoveryAck {
					return m, nil
				}
				m.returnToTab()
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
					m.defaultSavedNotice = true
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
		case homeThemePicker:
			return m.updateThemePicker(msg)
		case homeThemeConfirm:
			return m.updateThemeConfirm(msg)
		case homeConfirmDecrypt:
			return m.updateConfirmDecrypt(msg)
		case homePostEncrypt:
			return m.updatePostEncrypt(msg)
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
	if m.screen == homeThemePicker && m.themeFilter != "" {
		return true
	}
	return m.screen == homePicker && m.picker != nil && m.picker.filtering
}

func (m *Home) canSwitchTab(msg tea.KeyMsg) bool {
	if m.typing() {
		return false
	}
	if m.screen == homeConfirmDecrypt || m.screen == homePostEncrypt || m.screen == homeThemePicker || m.screen == homeThemeConfirm {
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
		m.applyTheme(m.settings.Theme)
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
	m.pendingIdentity = nil
	m.pendingOrigName = ""
	m.decryptDst = ""
	m.defaultSavedNotice = false
	m.postLocked, m.postOriginal, m.postRecovery = "", "", ""
	m.themeFilter, m.themePending = "", ""
	m.activateTab()
}

// updateSettings: ↑/↓ move the cursor, backspace toggles key type / auth,
// Enter on Theme opens the theme picker, A applies. Tab/←/→ leave for Help.
func (m *Home) updateSettings(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	const n = 3
	switch msg.String() {
	case "up", "k":
		m.setCursor = (m.setCursor - 1 + n) % n
	case "down", "j":
		m.setCursor = (m.setCursor + 1) % n
	case "enter":
		if m.setCursor == 2 {
			m.openThemePicker()
			return m, nil
		}
		m.toggleSetting(m.setCursor)
	case "backspace", " ":
		if m.setCursor == 2 {
			m.openThemePicker()
			return m, nil
		}
		m.toggleSetting(m.setCursor)
	case "a":
		if err := m.deps.Settings.Save(m.settings); err != nil {
			m.setResult("", err)
			return m, nil
		}
		m.applyTheme(m.settings.Theme)
		m.returnToTab()
	case "q":
		return m, tea.Quit
	}
	return m, nil
}

func (m *Home) toggleSetting(i int) {
	switch i {
	case 0:
		modes := []keystore.Mode{keystore.ModePassword, keystore.ModePIN, keystore.ModePassword2FA, keystore.ModePIN2FA}
		cur := 0
		for j, mm := range modes {
			if mm == m.settings.KeyType {
				cur = j
			}
		}
		m.settings.KeyType = modes[(cur+1)%len(modes)]
	case 1:
		m.settings.AuthEncrypt = !m.settings.AuthEncrypt
	}
}

func (m *Home) openThemePicker() {
	m.themeBefore = NormalizeTheme(m.settings.Theme)
	m.themeFilter = ""
	m.themePending = ""
	m.themeCursor = 0
	for i, id := range themeNames {
		if id == m.themeBefore {
			m.themeCursor = i
			break
		}
	}
	m.applyTheme(m.themeBefore)
	m.screen = homeThemePicker
}

func (m *Home) cancelThemePicker() {
	m.themeFilter = ""
	m.themePending = ""
	m.applyTheme(m.themeBefore)
	m.screen = homeSettings
}

func (m *Home) filteredThemes() []string {
	q := strings.ToLower(strings.TrimSpace(m.themeFilter))
	if q == "" {
		return themeNames
	}
	out := make([]string, 0, 32)
	for _, id := range themeNames {
		name := strings.ToLower(themeDisplayName(id))
		if strings.Contains(name, q) || strings.Contains(strings.ToLower(id), q) {
			out = append(out, id)
		}
	}
	return out
}

func (m *Home) clampThemeCursor() {
	n := len(m.filteredThemes())
	if n == 0 {
		m.themeCursor = 0
		return
	}
	if m.themeCursor < 0 {
		m.themeCursor = 0
	}
	if m.themeCursor >= n {
		m.themeCursor = n - 1
	}
}

func (m *Home) previewThemeAtCursor() {
	ids := m.filteredThemes()
	if len(ids) == 0 {
		m.applyTheme(m.themeBefore)
		return
	}
	m.clampThemeCursor()
	m.applyTheme(ids[m.themeCursor])
}

func (m *Home) updateThemePicker(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		if m.themeFilter != "" {
			m.themeFilter = ""
			m.clampThemeCursor()
			m.previewThemeAtCursor()
			return m, nil
		}
		m.cancelThemePicker()
		return m, nil
	case "enter":
		ids := m.filteredThemes()
		if len(ids) == 0 {
			return m, nil
		}
		m.clampThemeCursor()
		m.themePending = ids[m.themeCursor]
		m.applyTheme(m.themePending)
		m.screen = homeThemeConfirm
		return m, nil
	case "up", "k":
		if m.themeCursor > 0 {
			m.themeCursor--
			m.previewThemeAtCursor()
		}
		return m, nil
	case "down", "j":
		if m.themeCursor+1 < len(m.filteredThemes()) {
			m.themeCursor++
			m.previewThemeAtCursor()
		}
		return m, nil
	case "backspace":
		if m.themeFilter != "" {
			r := []rune(m.themeFilter)
			m.themeFilter = string(r[:len(r)-1])
			m.themeCursor = 0
			m.previewThemeAtCursor()
		}
		return m, nil
	case "q":
		if m.themeFilter == "" {
			return m, tea.Quit
		}
	}
	if msg.Type == tea.KeyRunes && len(msg.Runes) > 0 {
		m.themeFilter += string(msg.Runes)
		m.themeCursor = 0
		m.previewThemeAtCursor()
		return m, nil
	}
	return m, nil
}

func (m *Home) updateThemeConfirm(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "a", "enter", "y":
		if m.themePending == "" {
			m.screen = homeThemePicker
			return m, nil
		}
		m.settings.Theme = NormalizeTheme(m.themePending)
		if err := m.deps.Settings.Save(m.settings); err != nil {
			m.setResult("", err)
			return m, nil
		}
		m.applyTheme(m.settings.Theme)
		m.themePending = ""
		m.themeFilter = ""
		m.screen = homeSettings
		return m, nil
	case "esc", "n":
		m.themePending = ""
		m.previewThemeAtCursor()
		m.screen = homeThemePicker
		return m, nil
	case "q":
		return m, tea.Quit
	}
	return m, nil
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
	if action != "encrypt" {
		m.defaultSavedNotice = false
	}
	file := ""
	if action == "decrypt" {
		file = m.pendingPath
	}
	m.prompt = newSecretPrompt(m.deps, m.th, mode, action, file)
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
	res, err := auth.NewAuthenticator(m.deps.KDF, m.deps.Wrapper, m.deps.DevStore, m.deps.TOTP).
		Authenticate(m.pendingKS, []byte(msg.secret), msg.code)
	if err != nil {
		m.setResult("", errors.New("authentication failed; check the secret and the 2FA code"))
		return
	}
	if m.pendingKS.Mode.Has2FA() {
		step := res.NewTOTPStep
		m.pendingKS.LastTOTPStep = &step
		_ = m.deps.Vault.SaveKey(m.pendingPath, m.pendingKS)
	}
	identity, err := age.ParseX25519Identity(string(res.Identity))
	if err != nil {
		m.setResult("", err)
		return
	}
	dst, err := vault.DefaultUnlockPath(m.pendingPath, res.OriginalName)
	if err != nil {
		m.setResult("", err)
		return
	}
	m.pendingOrigName = res.OriginalName
	if _, err := os.Stat(dst); err == nil {
		m.pendingIdentity = identity
		m.decryptDst = dst
		m.screen = homeConfirmDecrypt
		return
	}
	m.finishDecrypt(identity, false)
}

func (m *Home) finishDecrypt(identity *age.X25519Identity, force bool) {
	origName := m.pendingOrigName
	dst, err := m.deps.Vault.Unlock(m.pendingPath, identity, vault.UnlockOptions{
		OriginalName: origName,
		Force:        force,
	})
	m.pendingIdentity = nil
	m.pendingOrigName = ""
	m.decryptDst = ""
	if err != nil {
		m.setResult("", err)
		return
	}
	m.setResult(keystore.FormatDecryptSuccess(dst), nil)
}

func (m *Home) updateConfirmDecrypt(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "y", "enter":
		if m.pendingIdentity == nil {
			m.setResult("", errors.New("decrypt state lost"))
			return m, nil
		}
		m.finishDecrypt(m.pendingIdentity, true)
	case "n", "esc":
		m.returnToTab()
	}
	return m, nil
}

// startEncryptWithSecret runs the encrypt flow with an already collected
// secret: the 2FA QR screen only when the shared install seed is missing.
func (m *Home) startEncryptWithSecret(mode keystore.Mode, secret string) {
	m.pendingMode = mode
	m.pendingSecret = secret
	if mode.Has2FA() {
		if m.deps.TOTPStore != nil {
			if ok, err := m.deps.TOTPStore.Exists(); err == nil && ok {
				seed, err := m.deps.TOTPStore.Load()
				if err != nil {
					m.setResult("", errors.New("cannot read shared 2FA seed"))
					return
				}
				m.doEncrypt(secret, seed)
				return
			}
		}
		seed, uri, err := m.deps.TOTP.GenerateSeed()
		if err != nil {
			m.setResult("", errors.New("cannot generate 2FA seed"))
			return
		}
		m.twofa = newTwofaPrompt(m.deps, m.th, seed, uri)
		m.screen = home2FA
		return
	}
	m.doEncrypt(secret, nil)
}

func (m *Home) run2FADone(msg twofaDoneMsg) {
	secret := m.pendingSecret
	m.pendingSecret = ""
	if m.deps.TOTPStore != nil {
		if err := m.deps.TOTPStore.Save(msg.seed); err != nil {
			m.setResult("", errors.New("cannot save shared 2FA seed"))
			return
		}
	}
	m.doEncrypt(secret, msg.seed)
}

func (m *Home) doEncrypt(secret string, seed []byte) {
	mode := m.pendingMode
	original := m.pendingPath
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
		[]byte(secret), devSecret, seed, keystore.DefaultArgon2Params, filepath.Base(original))
	if err != nil {
		m.setResult("", err)
		return
	}
	locked, err := m.deps.Vault.Lock(original, ks, vault.LockOptions{})
	if err != nil {
		m.setResult("", err)
		return
	}
	m.pendingSecret = ""
	m.postLocked = locked
	m.postOriginal = original
	m.postMode = mode
	m.postRecovery = identity.String()
	m.postPhase = postRecoveryAck
	m.screen = homePostEncrypt
}

func (m *Home) updatePostEncrypt(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch m.postPhase {
	case postRecoveryAck:
		if msg.Type == tea.KeyEnter || msg.String() == "y" {
			m.postPhase = postKeepOriginal
		}
	case postKeepOriginal:
		switch msg.String() {
		case "k", "enter":
			m.finishPostEncrypt(false)
		case "r":
			m.finishPostEncrypt(true)
		}
	}
	return m, nil
}

func (m *Home) finishPostEncrypt(removeOriginal bool) {
	if removeOriginal {
		if err := os.Remove(m.postOriginal); err != nil && !os.IsNotExist(err) {
			m.setResult("", fmt.Errorf("encrypted, but could not remove original: %w", err))
			return
		}
	}
	text := keystore.FormatEncryptSuccess(m.postLocked, m.postMode, removeOriginal, "")
	m.postLocked, m.postOriginal, m.postRecovery = "", "", ""
	m.setResult(text, nil)
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
	shared2FA := "not set"
	if m.deps.TOTPStore != nil {
		if ok, err := m.deps.TOTPStore.Exists(); err == nil && ok {
			shared2FA = "configured"
		}
	}
	device := "absent"
	if m.deps.DevStore != nil {
		if _, err := m.deps.DevStore.Load(); err == nil {
			device = "present"
		}
	}
	return fmt.Sprintf("default key type: %s\nrequire auth to encrypt: %t\ntheme: %s\nshared 2fa: %s\ndevice secret: %s\nsettings: %s\nversion: %s",
		keyType, m.settings.AuthEncrypt, themeDisplayName(m.settings.Theme), shared2FA, device, m.deps.Settings.Path(), m.deps.Version)
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
	b.WriteString(renderKeys(m.th, "Resize the window, or press {Q} to quit."))
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
	b.WriteString(renderKeys(m.th, footerKeys))
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
		b.WriteString("Default key type is not set yet.\n")
		b.WriteString(m.th.dim.Render("This choice applies to new encrypts. Each .pbx keeps its own mode.") + "\n\n")
		b.WriteString(m.chooser.View())
		return b.String()
	case homeSecret:
		notice := ""
		if m.defaultSavedNotice {
			notice = "Saved as the default for future encrypts. Change it in Settings."
		}
		return m.prompt.ContentViewWithNotice(notice)
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
		for i, line := range []string{
			"Default for new files: " + keyType,
			"Require authentication to encrypt: " + auth,
			"Theme: " + themeDisplayName(m.settings.Theme),
		} {
			if i == m.setCursor {
				b.WriteString("> " + m.th.selected.Render(line) + "\n")
			} else {
				b.WriteString("  " + line + "\n")
			}
		}
		b.WriteString("\n")
		b.WriteString(m.th.dim.Render("Changing the default does not alter existing .pbx files.") + "\n")
		if note := m.settings.KeyType.Shared2FANote(); note != "" {
			b.WriteString(m.th.dim.Render(note) + "\n")
		}
		b.WriteString(m.th.dim.Render("Theme: press Enter to open the theme picker.") + "\n")
		b.WriteString("\n" + renderKeys(m.th, "{↑}/{↓} move • {Backspace} toggle • {Enter} theme picker • {A} apply • {Tab} next section"))
		return b.String()
	case homeThemePicker:
		return m.themePickerView(innerH)
	case homeThemeConfirm:
		name := themeDisplayName(m.themePending)
		var b strings.Builder
		fmt.Fprintf(&b, "Apply %s?\n\n", name)
		b.WriteString(m.th.dim.Render("This screen already shows the colours.") + "\n\n")
		b.WriteString(renderKeys(m.th, "{A} apply • {Esc} cancel"))
		return b.String()
	case homeStatus:
		return "Status\n\n" + m.statusText
	case homeHelp:
		return "Help\n\n" + helpIntro + "\n\n" + helpFAQ + "\n\n" + renderKeys(m.th, helpText)
	case homeConfirmDecrypt:
		var b strings.Builder
		b.WriteString("Overwrite existing file?\n\n")
		b.WriteString(m.decryptDst + "\n\n")
		b.WriteString("That path already exists next to the .pbx.\n")
		b.WriteString(renderKeys(m.th, "{Enter}/{Y} overwrite • {N}/{Esc} cancel"))
		return b.String()
	case homePostEncrypt:
		return m.postEncryptView()
	case homeResult:
		if m.resultIsErr {
			return m.th.errS.Render(m.result)
		}
		return m.th.ok.Render(m.result)
	}
	return ""
}

func (m *Home) themePickerView(innerH int) string {
	ids := m.filteredThemes()
	m.clampThemeCursor()
	var b strings.Builder
	b.WriteString("Choose a theme\n")
	if m.themeFilter == "" {
		b.WriteString(m.th.dim.Render("Type to filter by name. Enter selects.") + "\n")
	} else {
		fmt.Fprintf(&b, "Filter: %s\n", m.themeFilter)
	}
	fmt.Fprintf(&b, "%d themes\n\n", len(ids))
	if len(ids) == 0 {
		b.WriteString(m.th.dim.Render("No themes match.") + "\n\n")
		b.WriteString(renderKeys(m.th, "{Backspace} edit filter • {Esc} clear or cancel"))
		return b.String()
	}
	// Leave room for the header and footer lines inside the box.
	listH := innerH - 6
	if listH < 3 {
		listH = 3
	}
	start := 0
	if m.themeCursor >= listH {
		start = m.themeCursor - listH + 1
	}
	end := start + listH
	if end > len(ids) {
		end = len(ids)
	}
	for i := start; i < end; i++ {
		line := themeDisplayName(ids[i])
		if i == m.themeCursor {
			b.WriteString("> " + m.th.selected.Render(line) + "\n")
		} else {
			b.WriteString("  " + line + "\n")
		}
	}
	b.WriteString("\n" + renderKeys(m.th, "{↑} {↓} move • type to filter • {Enter} select • {Esc} cancel"))
	return b.String()
}

func (m *Home) postEncryptView() string {
	var b strings.Builder
	switch m.postPhase {
	case postRecoveryAck:
		b.WriteString("Done. File encrypted successfully.\n")
		fmt.Fprintf(&b, "Saved at: %s\n", m.postLocked)
		fmt.Fprintf(&b, "This file was encrypted using %s, which will be required to open it.\n\n",
			m.postMode.CredentialPhrase())
		b.WriteString("Recovery key (shown once). Save it before continuing.\n")
		b.WriteString(m.postRecovery)
		b.WriteString("\n\n")
		b.WriteString(renderKeys(m.th, "{Enter} I saved the recovery key"))
	case postKeepOriginal:
		b.WriteString("The original file is still in the folder.\n")
		b.WriteString(m.postOriginal + "\n\n")
		b.WriteString("Press Enter to continue and keep it, or R to remove it.\n\n")
		b.WriteString(renderKeys(m.th, "{Enter}/{K} keep original • {R} remove original"))
	}
	return b.String()
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

func newSecretPrompt(d *Deps, th theme, mode keystore.Mode, action, file string) *secretPrompt {
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
		b.WriteString("Encrypt this file (" + string(p.mode) + ")\n\n")
	}
	for _, rule := range auth.SecretRules(p.mode) {
		b.WriteString(p.th.dim.Render(rule) + "\n")
	}
	if p.mode.Has2FA() && p.action != "decrypt" {
		b.WriteString(p.th.dim.Render(p.mode.Shared2FANote()) + "\n")
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

// ContentViewWithNotice prepends the first-run default-saved line when set.
func (p *secretPrompt) ContentViewWithNotice(notice string) string {
	if notice == "" {
		return p.ContentView()
	}
	return p.th.ok.Render(notice) + "\n\n" + p.ContentView()
}

func (p *secretPrompt) View() string {
	return fit(p.ContentView()+"\n\n"+renderKeys(p.th, "{Tab} next field • {Enter} continue • {Esc} back • {Ctrl+C} abort"), maxWidth, maxHeight)
}

// twofaPrompt shows the QR code of the install-wide TOTP seed and asks for one
// valid code. Ctrl+C copies the URI to the clipboard (does not quit).
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

func newTwofaPrompt(d *Deps, th theme, seed []byte, uri string) *twofaPrompt {
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
	b.WriteString("Set up 2FA for this install\n")
	qrLines := strings.Split(strings.TrimRight(p.qr, "\n"), "\n")
	side := []string{
		"One QR for this install.",
		"Ctrl+C copies URI (no quit).",
		"",
		"6-digit code:",
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
	return fit(p.ContentView()+"\n\n"+renderKeys(p.th, "{Enter} continue • {Esc} back • {Ctrl+C} copy 2fa uri"), maxWidth, maxHeight)
}
