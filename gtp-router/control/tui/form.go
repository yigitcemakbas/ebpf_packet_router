package tui

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/gtp-router/control/maps"
)

// actionOptions matches the canonical strings maps.ParseAction accepts, so
// the picker and the parser never disagree.
var actionOptions = []string{"drop", "decap", "encap", "redirect"}

type formField struct {
	label string
	input textinput.Model
}

// formModel is the add/edit rule form. The map key (TEID or UE IP) is only
// editable when adding a new rule; editing keeps the original key fixed and
// only lets the rest of the rule change.
type formModel struct {
	target   string // "teid" or "ueip"
	editing  bool
	origKey  uint32
	keyInput textinput.Model

	actionIdx int
	fields    []formField
	focusIdx  int

	err string
}

func newTextInput(placeholder string) textinput.Model {
	ti := textinput.New()
	ti.Placeholder = placeholder
	ti.CharLimit = 64
	ti.Width = 30
	return ti
}

func keyPlaceholder(target string) string {
	if target == "teid" {
		return "0xDEAD"
	}
	return "10.1.0.2"
}

func formatKey(target string, key uint32) string {
	if target == "teid" {
		return fmt.Sprintf("0x%08X", key)
	}
	return maps.Uint32ToIP(key).String()
}

func actionIndex(a uint32) int {
	for i, name := range actionOptions {
		if v, err := maps.ParseAction(name); err == nil && v == a {
			return i
		}
	}
	return 0
}

// defaultFields returns the field set for a map type, mirroring add_teid.go
// / add_ueip.go's flags: both have out-iface/dmac/smac/teid-out/dst-ip/
// src-ip; only TEID rules additionally have dst-port.
func defaultFields(target string) []formField {
	labels := []string{"Out-Iface", "DMac", "SMac", "Teid-Out", "Dst-IP", "Src-IP", "Rate-PPS"}
	if target == "teid" {
		labels = append(labels, "Dst-Port")
	}
	fields := make([]formField, len(labels))
	for i, l := range labels {
		fields[i] = formField{label: l, input: newTextInput("")}
	}
	return fields
}

func fieldValue(fields []formField, label string) string {
	for _, f := range fields {
		if f.label == label {
			return strings.TrimSpace(f.input.Value())
		}
	}
	return ""
}

func setFieldValue(fields []formField, label, val string) {
	for i := range fields {
		if fields[i].label == label {
			fields[i].input.SetValue(val)
		}
	}
}

func newAddForm(target string) *formModel {
	f := &formModel{
		target:   target,
		keyInput: newTextInput(keyPlaceholder(target)),
		fields:   defaultFields(target),
	}
	f.syncFocus()
	return f
}

// newEditForm pre-fills the form from rule's current values. rule may be
// nil if the selection is stale (e.g. the row vanished between selecting it
// and pressing 'e') - callers should check selectedRule's ok return first,
// but this stays defensive rather than panicking.
func newEditForm(target string, key uint32, rule *maps.FwdRule) *formModel {
	f := &formModel{
		target:   target,
		editing:  true,
		origKey:  key,
		keyInput: newTextInput(keyPlaceholder(target)),
		fields:   defaultFields(target),
	}
	f.keyInput.SetValue(formatKey(target, key))
	if rule == nil {
		f.syncFocus()
		return f
	}

	f.actionIdx = actionIndex(rule.Action)
	if rule.OutIfindex != 0 {
		if iface, err := net.InterfaceByIndex(int(rule.OutIfindex)); err == nil {
			setFieldValue(f.fields, "Out-Iface", iface.Name)
		}
	}
	if rule.DMac != [6]byte{} {
		setFieldValue(f.fields, "DMac", maps.MACString(rule.DMac))
	}
	if rule.SMac != [6]byte{} {
		setFieldValue(f.fields, "SMac", maps.MACString(rule.SMac))
	}
	if rule.TeidOut != 0 {
		setFieldValue(f.fields, "Teid-Out", fmt.Sprintf("0x%08X", rule.TeidOut))
	}
	if rule.DstIP != 0 {
		setFieldValue(f.fields, "Dst-IP", maps.Uint32ToIP(rule.DstIP).String())
	}
	if rule.SrcIP != 0 {
		setFieldValue(f.fields, "Src-IP", maps.Uint32ToIP(rule.SrcIP).String())
	}
	if rule.RatePPS != 0 {
		setFieldValue(f.fields, "Rate-PPS", fmt.Sprintf("%d", rule.RatePPS))
	}
	f.syncFocus()
	return f
}

// total is the number of focusable slots: the key field (add mode only),
// the action picker, then each text field.
func (f *formModel) total() int {
	n := 1 // action
	if !f.editing {
		n++
	}
	return n + len(f.fields)
}

// kindAt maps a flat focus index to what it refers to.
func (f *formModel) kindAt(idx int) (kind string, fieldIdx int) {
	pos := 0
	if !f.editing {
		if idx == pos {
			return "key", -1
		}
		pos++
	}
	if idx == pos {
		return "action", -1
	}
	pos++
	return "field", idx - pos
}

func (f *formModel) syncFocus() {
	if !f.editing {
		f.keyInput.Blur()
	}
	for i := range f.fields {
		f.fields[i].input.Blur()
	}
	switch kind, fi := f.kindAt(f.focusIdx); kind {
	case "key":
		f.keyInput.Focus()
	case "field":
		f.fields[fi].input.Focus()
	}
}

// parseHexOrDec parses a TEID-style value in hex ("0xDEAD") or decimal form.
// This duplicates control/cmd/util.go's parseTEID in miniature: that helper
// is unexported in package cmd, and cmd already imports this tui package
// (for the dashboard command), so importing the other way would be a cycle.
func parseHexOrDec(s string) (uint32, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("must not be empty")
	}
	var val uint64
	var err error
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		val, err = strconv.ParseUint(s[2:], 16, 32)
	} else {
		val, err = strconv.ParseUint(s, 10, 32)
	}
	if err != nil {
		return 0, fmt.Errorf("invalid value %q: must be hex (0xDEAD) or decimal", s)
	}
	return uint32(val), nil
}

// buildRule parses the form's current field values into a map key and a
// FwdRule, mirroring the parsing add_teid.go/add_ueip.go already do, and
// finishes with the same maps.ValidateRule check those commands use.
func (f *formModel) buildRule() (uint32, *maps.FwdRule, error) {
	action, err := maps.ParseAction(actionOptions[f.actionIdx])
	if err != nil {
		return 0, nil, err
	}

	var key uint32
	if f.editing {
		key = f.origKey
	} else if f.target == "teid" {
		key, err = parseHexOrDec(f.keyInput.Value())
		if err != nil {
			return 0, nil, fmt.Errorf("teid: %w", err)
		}
	} else {
		ip := net.ParseIP(f.keyInput.Value())
		if ip == nil || ip.To4() == nil {
			return 0, nil, fmt.Errorf("ip: invalid IPv4 address %q", f.keyInput.Value())
		}
		key, err = maps.IPToUint32(ip)
		if err != nil {
			return 0, nil, fmt.Errorf("ip: %w", err)
		}
	}

	rule := &maps.FwdRule{Action: action}

	if v := fieldValue(f.fields, "Out-Iface"); v != "" {
		iface, err := net.InterfaceByName(v)
		if err != nil {
			return 0, nil, fmt.Errorf("out-iface: %w", err)
		}
		rule.OutIfindex = uint32(iface.Index)
	}
	if v := fieldValue(f.fields, "DMac"); v != "" {
		mac, err := maps.ParseMAC(v)
		if err != nil {
			return 0, nil, fmt.Errorf("dmac: %w", err)
		}
		rule.DMac = mac
	}
	if v := fieldValue(f.fields, "SMac"); v != "" {
		mac, err := maps.ParseMAC(v)
		if err != nil {
			return 0, nil, fmt.Errorf("smac: %w", err)
		}
		rule.SMac = mac
	}
	if v := fieldValue(f.fields, "Teid-Out"); v != "" {
		t, err := parseHexOrDec(v)
		if err != nil {
			return 0, nil, fmt.Errorf("teid-out: %w", err)
		}
		rule.TeidOut = t
	}
	if v := fieldValue(f.fields, "Dst-IP"); v != "" {
		ip := net.ParseIP(v)
		if ip == nil {
			return 0, nil, fmt.Errorf("dst-ip: invalid IPv4 address %q", v)
		}
		if rule.DstIP, err = maps.IPToUint32(ip); err != nil {
			return 0, nil, fmt.Errorf("dst-ip: %w", err)
		}
	}
	if v := fieldValue(f.fields, "Src-IP"); v != "" {
		ip := net.ParseIP(v)
		if ip == nil {
			return 0, nil, fmt.Errorf("src-ip: invalid IPv4 address %q", v)
		}
		if rule.SrcIP, err = maps.IPToUint32(ip); err != nil {
			return 0, nil, fmt.Errorf("src-ip: %w", err)
		}
	}
	if v := fieldValue(f.fields, "Rate-PPS"); v != "" {
		p, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return 0, nil, fmt.Errorf("rate-pps: %w", err)
		}
		rule.RatePPS = uint32(p)
	}
	if f.target == "teid" {
		if v := fieldValue(f.fields, "Dst-Port"); v != "" {
			p, err := strconv.ParseUint(v, 10, 16)
			if err != nil {
				return 0, nil, fmt.Errorf("dst-port: %w", err)
			}
			// Same byte-order juggling as add_teid.go's --dst-port handling.
			b := make([]byte, 2)
			binary.BigEndian.PutUint16(b, uint16(p))
			rule.DstPort = binary.LittleEndian.Uint16(b)
		}
	}

	if err := maps.ValidateRule(rule); err != nil {
		return 0, nil, err
	}

	return key, rule, nil
}

// updateForm handles key input while the add/edit form is shown.
func (m model) updateForm(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	f := m.form

	switch msg.String() {
	case "esc":
		m.mode = modeView
		m.form = nil
		return m, nil

	case "tab":
		f.focusIdx = (f.focusIdx + 1) % f.total()
		f.syncFocus()
		return m, nil

	case "shift+tab":
		f.focusIdx = (f.focusIdx - 1 + f.total()) % f.total()
		f.syncFocus()
		return m, nil

	case "left", "right":
		if kind, _ := f.kindAt(f.focusIdx); kind == "action" {
			if msg.String() == "left" {
				f.actionIdx = (f.actionIdx - 1 + len(actionOptions)) % len(actionOptions)
			} else {
				f.actionIdx = (f.actionIdx + 1) % len(actionOptions)
			}
			return m, nil
		}

	case "enter":
		key, rule, err := f.buildRule()
		if err != nil {
			f.err = err.Error()
			return m, nil
		}
		if f.target == "teid" {
			err = m.tm.Put(key, rule)
		} else {
			err = m.um.Put(maps.Uint32ToIP(key), rule)
		}
		if err != nil {
			f.err = err.Error()
			return m, nil
		}
		m.mode = modeView
		m.form = nil
		return m, m.fetchCmd()
	}

	// Forward anything else (typed characters, backspace, cursor movement
	// within a field) to whichever input currently has focus.
	var cmd tea.Cmd
	switch kind, fi := f.kindAt(f.focusIdx); kind {
	case "key":
		f.keyInput, cmd = f.keyInput.Update(msg)
	case "field":
		f.fields[fi].input, cmd = f.fields[fi].input.Update(msg)
	}
	return m, cmd
}

func (m model) renderForm() string {
	f := m.form
	var b strings.Builder

	title := "Add rule"
	if f.editing {
		title = "Edit rule"
	}
	b.WriteString(titleStyle.Render(title + " (" + f.target + "_map)"))
	b.WriteString("\n\n")

	kind, _ := f.kindAt(f.focusIdx)

	keyLabel := "TEID"
	if f.target == "ueip" {
		keyLabel = "UE IP"
	}
	if f.editing {
		fmt.Fprintf(&b, "  %-10s %s (fixed)\n", keyLabel, f.keyInput.Value())
	} else {
		marker := "  "
		if kind == "key" {
			marker = "> "
		}
		fmt.Fprintf(&b, "%s%-10s %s\n", marker, keyLabel, f.keyInput.View())
	}

	actionMarker := "  "
	if kind == "action" {
		actionMarker = "> "
	}
	fmt.Fprintf(&b, "%s%-10s < %s >\n", actionMarker, "Action", actionOptions[f.actionIdx])

	for i, fld := range f.fields {
		marker := "  "
		if k, fi := f.kindAt(f.focusIdx); k == "field" && fi == i {
			marker = "> "
		}
		fmt.Fprintf(&b, "%s%-10s %s\n", marker, fld.label, fld.input.View())
	}

	if f.err != "" {
		b.WriteString("\n")
		b.WriteString(errorStyle.Render("error: " + f.err))
	}

	b.WriteString("\n\n")
	b.WriteString(footerStyle.Render("tab: next field   left/right: change action   enter: submit   esc: cancel"))

	return panelStyle.Render(b.String())
}
