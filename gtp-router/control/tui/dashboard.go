// Package tui implements a live, auto-refreshing terminal dashboard for
// gtp-ctrl: both forwarding-rule tables (teid_map, ueip_map) and the global
// XDP verdict counters (PASS/DROP/REDIRECT), each with a derived live
// packets-per-second figure. It reads the same pinned BPF maps as
// `gtp-ctrl list` / `gtp-ctrl stats`, via the same control/maps and
// control/stats helpers - this package only adds the render loop and the
// pps delta calculation on top.
package tui

import (
	"fmt"
	"sort"
	"time"

	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/gtp-router/control/maps"
	"github.com/gtp-router/control/stats"
)

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

	teidTable table.Model
	ueipTable table.Model

	haveData bool
	lastTeid map[uint32]*maps.FwdRule
	lastUeip map[uint32]*maps.FwdRule
	lastStat *stats.Counters
	prevStat *stats.Counters
	lastAt   time.Time
	elapsed  float64

	updatedAt time.Time
	err       error
}

func newModel(tm *maps.TeidMap, um *maps.UeipMap, interval time.Duration) model {
	teidCols := []table.Column{
		{Title: "TEID", Width: 12},
		{Title: "ACTION", Width: 10},
		{Title: "IFINDEX", Width: 7},
		{Title: "DST MAC", Width: 17},
		{Title: "SRC MAC", Width: 17},
		{Title: "PACKETS", Width: 10},
		{Title: "BYTES", Width: 10},
		{Title: "PPS", Width: 8},
	}
	ueipCols := []table.Column{
		{Title: "UE IP", Width: 15},
		{Title: "ACTION", Width: 10},
		{Title: "IFINDEX", Width: 7},
		{Title: "DST MAC", Width: 17},
		{Title: "SRC MAC", Width: 17},
		{Title: "PACKETS", Width: 10},
		{Title: "BYTES", Width: 10},
		{Title: "PPS", Width: 8},
	}

	return model{
		tm:        tm,
		um:        um,
		interval:  interval,
		teidTable: table.New(table.WithColumns(teidCols), table.WithHeight(8)),
		ueipTable: table.New(table.WithColumns(ueipCols), table.WithHeight(8)),
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
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		}
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

		m.teidTable.SetRows(buildRows(msg.teid, m.lastTeid, elapsed, m.haveData, formatTEID))
		m.ueipTable.SetRows(buildRows(msg.ueip, m.lastUeip, elapsed, m.haveData, formatUEIP))

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

func pps(curr, prev uint64, elapsed float64, havePrev bool) float64 {
	if !havePrev || elapsed <= 0 || curr < prev {
		return 0
	}
	return float64(curr-prev) / elapsed
}

func buildRows(curr, prev map[uint32]*maps.FwdRule, elapsed float64, havePrev bool, keyFmt func(uint32) string) []table.Row {
	keys := make([]uint32, 0, len(curr))
	for k := range curr {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })

	rows := make([]table.Row, 0, len(keys))
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

		rows = append(rows, table.Row{
			keyFmt(k),
			maps.ActionString(r.Action),
			fmt.Sprintf("%d", r.OutIfindex),
			maps.MACString(r.DMac),
			maps.MACString(r.SMac),
			fmt.Sprintf("%d", r.PktCount),
			maps.FormatBytes(r.ByteCount),
			fmt.Sprintf("%.1f/s", p),
		})
	}
	return rows
}

func (m model) View() string {
	if m.err != nil {
		return errorStyle.Render("ERROR: "+m.err.Error()) +
			"\n\nIs the XDP program loaded? Run: sudo bash tools/setup_netns.sh\n\n" +
			footerStyle.Render("q: quit   ctrl+c: quit")
	}

	header := titleStyle.Render("GTP-U XDP Router - Live Dashboard")
	if !m.updatedAt.IsZero() {
		header += fmt.Sprintf("   (refresh: %s, updated: %s)", m.interval, m.updatedAt.Format("15:04:05"))
	} else {
		header += "   (loading...)"
	}

	teidPanel := panelStyle.Render(titleStyle.Render("teid_map") + "\n" + m.teidTable.View())
	ueipPanel := panelStyle.Render(titleStyle.Render("ueip_map") + "\n" + m.ueipTable.View())
	statsPanel := panelStyle.Render(titleStyle.Render("global verdict counters") + "\n" + m.renderStats())

	footer := footerStyle.Render("q: quit   ctrl+c: quit")

	return header + "\n\n" + teidPanel + "\n" + ueipPanel + "\n" + statsPanel + "\n\n" + footer
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
