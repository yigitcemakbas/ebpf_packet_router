// Package tui implements a live, auto-refreshing terminal dashboard for
// gtp-ctrl: both forwarding-rule tables (teid_map, ueip_map) and the global
// XDP verdict counters (PASS/DROP/REDIRECT), each with a derived live
// packets-per-second figure. It reads the same pinned BPF maps as
// `gtp-ctrl list` / `gtp-ctrl stats`, via the same control/maps and
// control/stats helpers - this package only adds the render loop and the
// pps delta calculation on top.
package tui

import (
	"encoding/base64"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/gtp-router/control/maps"
	"github.com/gtp-router/control/stats"
)

// defaultWidth is assumed until the first tea.WindowSizeMsg arrives, so the
// dashboard doesn't flash a "too narrow" notice for one frame on startup.
const defaultWidth = 80

// Width tiers for the rule panels. Columns deliberately omit DST MAC/SRC MAC
// (static config already shown in full by `gtp-ctrl list`) even at full
// width - the dashboard's job is the live counters, not re-displaying
// config. DROPPED (rate-limit drops) is prioritized above BYTES, since
// PACKETS+PPS already convey volume/rate and DROPPED is the differentiating
// signal for the per-subscriber rate limiting feature - a standard 80-column
// terminal lands in the medium tier, which keeps DROPPED and drops BYTES;
// widen to 90+ columns to see BYTES too.
const (
	fullWidthThreshold   = 90
	mediumWidthThreshold = 60
)

// columnsFor returns the headers/widths for a rule panel's key column (TEID
// or UE IP) at the given terminal width. tooNarrow is true when there isn't
// enough room for any table layout, in which case the caller should show a
// plain notice instead of attempting to render columns. These rule tables are
// forwarding-focused: rate-limit/quarantine policy lives in its own
// Enforcement panel (renderEnforcement), so nothing here competes for width
// and BYTES can stay in the full tier.
func columnsFor(width int, keyLabel string, keyWidth int) (headers []string, widths []int, tooNarrow bool) {
	switch {
	case width >= fullWidthThreshold:
		return []string{keyLabel, "ACTION", "IFINDEX", "PACKETS", "BYTES", "PPS"},
			[]int{keyWidth, 10, 5, 8, 10, 7}, false
	case width >= mediumWidthThreshold:
		return []string{keyLabel, "ACTION", "IFINDEX", "PACKETS", "PPS"},
			[]int{keyWidth, 10, 5, 8, 7}, false
	default:
		return nil, nil, true
	}
}

// dropColumn removes column idx from every row, used when the medium-width
// layout drops BYTES (index 4 in the row produced by buildRows) without
// needing buildRows itself to know about rendering width.
func dropColumn(rows [][]string, idx int) [][]string {
	out := make([][]string, len(rows))
	for i, r := range rows {
		nr := make([]string, 0, len(r))
		for j, c := range r {
			if j == idx {
				continue
			}
			nr = append(nr, c)
		}
		out[i] = nr
	}
	return out
}

// asciiBorder avoids all non-ASCII box-drawing characters, matching the
// project's ASCII-only output policy (see the "Removed non-ASCII characters"
// history in this repo).
var asciiBorder = lipgloss.Border{
	Top:         "-",
	Bottom:      "-",
	Left:        "|",
	Right:       "|",
	TopLeft:     "+",
	TopRight:    "+",
	BottomLeft:  "+",
	BottomRight: "+",
}

var (
	panelStyle  = lipgloss.NewStyle().Border(asciiBorder).Padding(0, 1)
	titleStyle  = lipgloss.NewStyle().Bold(true)
	footerStyle = lipgloss.NewStyle().Faint(true)
	errorStyle  = lipgloss.NewStyle().Bold(true)
)

// Run starts the dashboard. It opens teid_map/ueip_map once for the life of
// the program and closes them on exit; stats_map is opened per refresh via
// stats.Read, mirroring `gtp-ctrl stats --watch`.
func Run(interval time.Duration) error {
	tm, err := maps.OpenTeidMap()
	if err != nil {
		return fmt.Errorf("dashboard: %w (is the XDP program loaded? run setup_netns.sh / gtp-ctrl load)", err)
	}
	defer tm.Close()

	um, err := maps.OpenUeipMap()
	if err != nil {
		return fmt.Errorf("dashboard: %w (is the XDP program loaded? run setup_netns.sh / gtp-ctrl load)", err)
	}
	defer um.Close()

	m := newModel(tm, um, interval)
	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err = p.Run()
	return err
}

// mode selects which of the three sub-views Update/View dispatch to.
type uiMode int

const (
	modeView uiMode = iota
	modeForm
	modeConfirmDelete
)

// panelFocus selects which rule panel keyboard navigation (Tab/Up/Down/
// a/e/d) currently applies to.
type panelFocus int

const (
	focusTeid panelFocus = iota
	focusUeip
)

type tickMsg time.Time

type dataMsg struct {
	teid      map[uint32]*maps.FwdRule
	ueip      map[uint32]*maps.FwdRule
	counters  *stats.Counters
	fetchedAt time.Time
	err       error
}

type model struct {
	tm *maps.TeidMap
	um *maps.UeipMap

	interval time.Duration
	width    int

	mode  uiMode
	focus panelFocus

	teidRows     [][]string
	ueipRows     [][]string
	teidKeys     []uint32
	ueipKeys     []uint32
	teidSelected int
	ueipSelected int

	form          *formModel
	confirmTarget string
	confirmKey    uint32

	haveData bool
	lastTeid map[uint32]*maps.FwdRule
	lastUeip map[uint32]*maps.FwdRule
	lastStat *stats.Counters
	prevStat *stats.Counters
	lastAt   time.Time
	elapsed  float64

	updatedAt time.Time
	err       error

	statusMsg   string
	statusUntil time.Time
}

func newModel(tm *maps.TeidMap, um *maps.UeipMap, interval time.Duration) model {
	return model{
		tm:       tm,
		um:       um,
		interval: interval,
		width:    defaultWidth,
	}
}

func (m model) Init() tea.Cmd {
	return tea.Batch(m.fetchCmd(), tickCmd(m.interval))
}

func (m model) fetchCmd() tea.Cmd {
	tm, um := m.tm, m.um
	return func() tea.Msg {
		teidEntries, err := tm.List()
		if err != nil {
			return dataMsg{err: fmt.Errorf("teid_map: %w", err)}
		}
		ueipEntries, err := um.List()
		if err != nil {
			return dataMsg{err: fmt.Errorf("ueip_map: %w", err)}
		}
		c, err := stats.Read(maps.PinStatsMap)
		if err != nil {
			return dataMsg{err: fmt.Errorf("stats_map: %w", err)}
		}
		return dataMsg{teid: teidEntries, ueip: ueipEntries, counters: c, fetchedAt: time.Now()}
	}
}

func tickCmd(interval time.Duration) tea.Cmd {
	return tea.Tick(interval, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		return m, nil

	case tea.KeyMsg:
		switch m.mode {
		case modeForm:
			return m.updateForm(msg)
		case modeConfirmDelete:
			return m.updateConfirmDelete(msg)
		default:
			return m.updateView(msg)
		}

	case copyResultMsg:
		if msg.err != nil {
			m.statusMsg = "snapshot failed: " + msg.err.Error()
		} else {
			m.statusMsg = "saved snapshot to " + msg.path + " (cat it, or copy from your editor)"
		}
		m.statusUntil = time.Now().Add(6 * time.Second)
		return m, nil

	case tickMsg:
		return m, tea.Batch(m.fetchCmd(), tickCmd(m.interval))

	case dataMsg:
		if msg.err != nil {
			m.err = msg.err
			return m, nil
		}
		m.err = nil

		elapsed := 0.0
		if m.haveData {
			elapsed = msg.fetchedAt.Sub(m.lastAt).Seconds()
		}

		m.teidKeys, m.teidRows = buildRows(msg.teid, m.lastTeid, elapsed, m.haveData, formatTEID)
		m.ueipKeys, m.ueipRows = buildRows(msg.ueip, m.lastUeip, elapsed, m.haveData, formatUEIP)
		m.teidSelected = clamp(m.teidSelected, 0, max(len(m.teidKeys)-1, 0))
		m.ueipSelected = clamp(m.ueipSelected, 0, max(len(m.ueipKeys)-1, 0))

		m.lastTeid = msg.teid
		m.lastUeip = msg.ueip
		m.prevStat = m.lastStat
		m.lastStat = msg.counters
		m.elapsed = elapsed
		m.lastAt = msg.fetchedAt
		m.haveData = true
		m.updatedAt = msg.fetchedAt

		return m, nil
	}

	return m, nil
}

func formatTEID(key uint32) string { return fmt.Sprintf("0x%08X", key) }
func formatUEIP(key uint32) string { return maps.Uint32ToIP(key).String() }

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// updateView handles key input while the live dashboard (not a form or
// delete confirmation) is shown: panel focus, row selection, and opening the
// add/edit/delete sub-views.
func (m model) updateView(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "ctrl+c":
		return m, tea.Quit

	case "tab":
		if m.focus == focusTeid {
			m.focus = focusUeip
		} else {
			m.focus = focusTeid
		}
		return m, nil

	case "up", "k":
		m.moveSelection(-1)
		return m, nil

	case "down", "j":
		m.moveSelection(1)
		return m, nil

	case "a":
		m.mode = modeForm
		m.form = newAddForm(m.focusTarget())
		return m, nil

	case "e", "enter":
		key, rule, ok := m.selectedRule()
		if !ok {
			return m, nil
		}
		m.mode = modeForm
		m.form = newEditForm(m.focusTarget(), key, rule)
		return m, nil

	case "d", "x":
		key, _, ok := m.selectedRule()
		if !ok {
			return m, nil
		}
		m.mode = modeConfirmDelete
		m.confirmTarget = m.focusTarget()
		m.confirmKey = key
		return m, nil

	case "c":
		return m, copyCmd(m.plainSnapshot())
	}
	return m, nil
}

// snapshotPath is a fixed location so "c" always saves to the same place.
const snapshotPath = "/tmp/gtp-dashboard-snapshot.txt"

type copyResultMsg struct {
	path string
	err  error
}

// copyCmd saves the current snapshot to a fixed file - the reliable part,
// since it doesn't depend on terminal/tmux clipboard support - and also
// attempts an OSC 52 "set clipboard" escape sequence as a best-effort bonus
// (some terminals pick this up, others silently ignore it; failure there
// doesn't affect the file write). Either way, the snapshot now sits
// somewhere static that isn't overwritten a second later, so it can be
// opened and copied at your own pace.
func copyCmd(content string) tea.Cmd {
	return func() tea.Msg {
		if err := os.WriteFile(snapshotPath, []byte(content), 0644); err != nil {
			return copyResultMsg{err: err}
		}
		encoded := base64.StdEncoding.EncodeToString([]byte(content))
		fmt.Fprintf(os.Stdout, "\x1b]52;c;%s\x07", encoded) // best-effort; errors ignored
		return copyResultMsg{path: snapshotPath}
	}
}

// plainSnapshot renders the current dashboard state as plain ASCII text -
// no lipgloss styling, so nothing pastes as garbled escape codes. Reuses
// the exact same renderPanel/renderStats helpers the live view uses; only
// the lipgloss border/title wrapping is skipped.
func (m model) plainSnapshot() string {
	var b strings.Builder
	fmt.Fprintf(&b, "GTP-U XDP Router - Dashboard Snapshot (%s)\n\n", time.Now().Format("2006-01-02 15:04:05"))

	b.WriteString("teid_map\n")
	b.WriteString(m.renderPanel("TEID", 12, m.teidRows, -1))
	b.WriteString("\n")

	b.WriteString("ueip_map\n")
	b.WriteString(m.renderPanel("UE IP", 15, m.ueipRows, -1))
	b.WriteString("\n")

	b.WriteString("enforcement (rate-limit / quarantine)\n")
	b.WriteString(m.renderEnforcement())
	b.WriteString("\n")

	b.WriteString("global verdict counters\n")
	b.WriteString(m.renderStats())

	return b.String()
}

func (m *model) focusTarget() string {
	if m.focus == focusTeid {
		return "teid"
	}
	return "ueip"
}

func (m *model) moveSelection(delta int) {
	if m.focus == focusTeid {
		n := len(m.teidKeys)
		if n == 0 {
			return
		}
		m.teidSelected = clamp(m.teidSelected+delta, 0, n-1)
		return
	}
	n := len(m.ueipKeys)
	if n == 0 {
		return
	}
	m.ueipSelected = clamp(m.ueipSelected+delta, 0, n-1)
}

// selectedRule returns the map key and current rule for whichever panel has
// focus, reading from the last fetched snapshot (lastTeid/lastUeip) rather
// than the rendered string rows, so an edit form can be pre-filled with the
// real field values.
func (m *model) selectedRule() (uint32, *maps.FwdRule, bool) {
	if m.focus == focusTeid {
		if m.teidSelected < 0 || m.teidSelected >= len(m.teidKeys) {
			return 0, nil, false
		}
		key := m.teidKeys[m.teidSelected]
		return key, m.lastTeid[key], true
	}
	if m.ueipSelected < 0 || m.ueipSelected >= len(m.ueipKeys) {
		return 0, nil, false
	}
	key := m.ueipKeys[m.ueipSelected]
	return key, m.lastUeip[key], true
}

// updateConfirmDelete handles the y/n delete-confirmation prompt.
func (m model) updateConfirmDelete(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "y", "enter":
		var err error
		if m.confirmTarget == "teid" {
			err = m.tm.Delete(m.confirmKey)
		} else {
			err = m.um.Delete(maps.Uint32ToIP(m.confirmKey))
		}
		m.mode = modeView
		if err != nil {
			m.err = err
			return m, nil
		}
		return m, m.fetchCmd()

	case "n", "esc":
		m.mode = modeView
		return m, nil
	}
	return m, nil
}

func (m model) renderConfirm() string {
	label := fmt.Sprintf("0x%08X", m.confirmKey)
	if m.confirmTarget == "ueip" {
		label = maps.Uint32ToIP(m.confirmKey).String()
	}
	body := fmt.Sprintf("Delete %s rule for %s ?\n\n", m.confirmTarget, label) +
		footerStyle.Render("y: confirm   n/esc: cancel")
	return panelStyle.Render(titleStyle.Render("Confirm delete") + "\n\n" + body)
}

// enforcementState summarizes a rule's quarantine posture for the Enforcement
// panel: "HELD" while actively quarantined, "armed" when quarantine is
// configured but not currently tripped, "-" when no quarantine is set (e.g. a
// rate-limit-only rule). QuarantineUntilNs is a bpf_ktime_get_ns()
// (CLOCK_MONOTONIC) deadline set by the XDP program, so it's compared against
// maps.MonotonicNowNs(), not time.Now() (wall-clock; wrong clock domain).
func enforcementState(r *maps.FwdRule) string {
	if r.QuarantineUntilNs != 0 && maps.MonotonicNowNs() < r.QuarantineUntilNs {
		return "HELD"
	}
	if r.QuarantineThreshold > 0 {
		return "armed"
	}
	return "-"
}

func pps(curr, prev uint64, elapsed float64, havePrev bool) float64 {
	if !havePrev || elapsed <= 0 || curr < prev {
		return 0
	}
	return float64(curr-prev) / elapsed
}

// buildRows returns the sorted keys alongside their rendered rows, in the
// same order, so a selection index can be mapped back to a real map key
// (and from there to the underlying *maps.FwdRule for edit/delete).
func buildRows(curr, prev map[uint32]*maps.FwdRule, elapsed float64, havePrev bool, keyFmt func(uint32) string) ([]uint32, [][]string) {
	keys := make([]uint32, 0, len(curr))
	for k := range curr {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })

	rows := make([][]string, 0, len(keys))
	for _, k := range keys {
		r := curr[k]
		var prevPkts uint64
		havePrevKey := havePrev
		if p, ok := prev[k]; ok {
			prevPkts = p.PktCount
		} else {
			havePrevKey = false
		}
		p := pps(r.PktCount, prevPkts, elapsed, havePrevKey)

		rows = append(rows, []string{
			keyFmt(k),
			maps.ActionString(r.Action),
			fmt.Sprintf("%d", r.OutIfindex),
			fmt.Sprintf("%d", r.PktCount),
			maps.FormatBytes(r.ByteCount),
			fmt.Sprintf("%.1f/s", p),
		})
	}
	return keys, rows
}

// enforcementRows builds the Enforcement panel's rows: every rule (from either
// map) that has a rate cap or a quarantine configured, in TEID-then-UEIP order.
// It reads the raw rules (not the pre-rendered forwarding rows) so it can show
// the configured policy - CAP and QUAR threshold/timer - not just its effects.
func enforcementRows(teid, ueip map[uint32]*maps.FwdRule) [][]string {
	rows := [][]string{}
	collect := func(m map[uint32]*maps.FwdRule, keyFmt func(uint32) string) {
		keys := make([]uint32, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
		for _, k := range keys {
			r := m[k]
			if r.RatePPS == 0 && r.QuarantineThreshold == 0 {
				continue
			}
			capStr := "-"
			if r.RatePPS > 0 {
				capStr = fmt.Sprintf("%d/s", r.RatePPS)
			}
			quar := "-"
			if r.QuarantineThreshold > 0 {
				quar = fmt.Sprintf("%d/%ds", r.QuarantineThreshold, r.QuarantineSeconds)
			}
			rows = append(rows, []string{
				keyFmt(k),
				capStr,
				fmt.Sprintf("%d", r.RateDropCount),
				quar,
				enforcementState(r),
			})
		}
	}
	collect(teid, formatTEID)
	collect(ueip, formatUEIP)
	return rows
}

// renderTable formats headers and rows as fixed-width, left-justified plain
// text, the same approach already used by `gtp-ctrl list` (tabwriter) and
// the global verdict panel below - no external table widget involved. The
// selected row (if any, -1 for none) gets a plain ASCII "> " marker instead
// of a styling/color approach, since mixing ANSI styling into fixed-width
// Sprintf padding is exactly the kind of thing that caused the earlier
// bubbles/table rendering bug - a plain marker column can't misalign.
func renderTable(headers []string, widths []int, rows [][]string, selected int) string {
	var b strings.Builder

	writeRow := func(marker string, cells []string) {
		b.WriteString(marker)
		for i, w := range widths {
			cell := ""
			if i < len(cells) {
				cell = cells[i]
			}
			fmt.Fprintf(&b, "%-*s  ", w, cell)
		}
		b.WriteString("\n")
	}

	writeRow("  ", headers)
	seps := make([]string, len(widths))
	for i, w := range widths {
		seps[i] = strings.Repeat("-", w)
	}
	writeRow("  ", seps)

	if len(rows) == 0 {
		b.WriteString("  (empty)\n")
	}
	for i, r := range rows {
		marker := "  "
		if i == selected {
			marker = "> "
		}
		writeRow(marker, r)
	}
	return b.String()
}

func (m model) View() string {
	if m.err != nil {
		return errorStyle.Render("ERROR: "+m.err.Error()) +
			"\n\nIs the XDP program loaded? Run: sudo bash tools/setup_netns.sh\n\n" +
			footerStyle.Render("q: quit   ctrl+c: quit")
	}

	switch m.mode {
	case modeForm:
		return m.renderForm()
	case modeConfirmDelete:
		return m.renderConfirm()
	default:
		return m.renderView()
	}
}

func (m model) renderView() string {
	header := titleStyle.Render("GTP-U XDP Router - Live Dashboard")
	if !m.updatedAt.IsZero() {
		header += fmt.Sprintf("   (refresh: %s, updated: %s)", m.interval, m.updatedAt.Format("15:04:05"))
	} else {
		header += "   (loading...)"
	}

	teidTitle, ueipTitle := "  teid_map", "  ueip_map"
	teidSel, ueipSel := -1, -1
	if m.focus == focusTeid {
		teidTitle = "> teid_map"
		teidSel = m.teidSelected
	} else {
		ueipTitle = "> ueip_map"
		ueipSel = m.ueipSelected
	}

	teidPanel := panelStyle.Render(titleStyle.Render(teidTitle) + "\n" + m.renderPanel("TEID", 12, m.teidRows, teidSel))
	ueipPanel := panelStyle.Render(titleStyle.Render(ueipTitle) + "\n" + m.renderPanel("UE IP", 15, m.ueipRows, ueipSel))
	enforcePanel := panelStyle.Render(titleStyle.Render("  enforcement (rate-limit / quarantine)") + "\n" + m.renderEnforcement())
	statsPanel := panelStyle.Render(titleStyle.Render("global verdict counters") + "\n" + m.renderStats())

	footer := footerStyle.Render("tab: switch panel   up/down: select   a: add   e: edit   d: delete   c: snapshot   q: quit")
	if time.Now().Before(m.statusUntil) {
		footer = footerStyle.Render(m.statusMsg) + "\n" + footer
	}

	return header + "\n\n" + teidPanel + "\n" + ueipPanel + "\n" + enforcePanel + "\n" + statsPanel + "\n\n" + footer
}

// renderPanel picks the column set for the current terminal width and
// renders the corresponding rows, dropping BYTES from the full 8-column row
// produced by buildRows when the medium-width tier is in effect.
func (m model) renderPanel(keyLabel string, keyWidth int, rows [][]string, selected int) string {
	headers, widths, tooNarrow := columnsFor(m.width, keyLabel, keyWidth)
	if tooNarrow {
		return "(terminal too narrow for table view - resize to at least 60 columns)"
	}
	if len(headers) == 5 {
		rows = dropColumn(rows, 4) // full row is [key, action, ifindex, packets, bytes, pps]; medium drops bytes
	}
	return renderTable(headers, widths, rows, selected)
}

// renderEnforcement renders the Enforcement panel - the per-subscriber
// rate-limit / quarantine policy that a normal router cannot express. It is a
// read-only status view; edits happen on the subscriber's rule (a/e in the
// rule panels, or the ratelimit/quarantine control-plane verbs), since policy
// is an attribute of the rule, not a separate object.
func (m model) renderEnforcement() string {
	rows := enforcementRows(m.lastTeid, m.lastUeip)
	if len(rows) == 0 {
		return "  (no rate-limit or quarantine policy set)"
	}
	headers := []string{"SUBSCRIBER", "CAP", "DROPPED", "QUAR", "STATE"}
	widths := []int{15, 8, 8, 10, 6}
	return renderTable(headers, widths, rows, -1)
}

func (m model) renderStats() string {
	if m.lastStat == nil {
		return "(no data yet)"
	}

	havePrev := m.prevStat != nil
	verdicts := []struct {
		name string
		cur  stats.VerdictStat
		prev stats.VerdictStat
	}{
		{"PASS", m.lastStat.Pass, stats.VerdictStat{}},
		{"DROP", m.lastStat.Drop, stats.VerdictStat{}},
		{"REDIRECT", m.lastStat.Redirect, stats.VerdictStat{}},
	}
	if havePrev {
		verdicts[0].prev = m.prevStat.Pass
		verdicts[1].prev = m.prevStat.Drop
		verdicts[2].prev = m.prevStat.Redirect
	}

	out := fmt.Sprintf("%-10s  %12s  %12s  %10s\n", "VERDICT", "PACKETS", "BYTES", "PPS")
	out += fmt.Sprintf("%-10s  %12s  %12s  %10s\n", "-------", "-------", "-----", "---")
	for _, v := range verdicts {
		p := pps(v.cur.Packets, v.prev.Packets, m.elapsed, havePrev)
		out += fmt.Sprintf("%-10s  %12d  %12s  %9.1f/s\n", v.name, v.cur.Packets, stats.FormatBytes(v.cur.Bytes), p)
	}
	return out
}
