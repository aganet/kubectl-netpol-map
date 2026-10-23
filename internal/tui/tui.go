// Package tui is the full-screen terminal app, in the style of k9s:
// namespaces on the left, the policies, connections or workloads of the
// selected namespace in the middle, the detail of the selected item below.
package tui

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/yaml"

	"github.com/aganet/kubectl-netpol-map/internal/lint"
	"github.com/aganet/kubectl-netpol-map/internal/policy"
)

type view int

const (
	viewPolicies view = iota
	viewConnections
	viewWorkloads
)

type pane int

const (
	paneNS pane = iota
	paneList
	paneDetail
)

const nsPaneWidth = 24

// workload is a workload with what the policies say about it.
type workload struct {
	ref        policy.WorkloadRef
	I, E       bool
	selectedBy []string
	peerOf     []string
}

type data struct {
	snap       *policy.Snapshot
	policies   []policy.PolicyView
	coverage   policy.Coverage
	findings   []lint.Finding
	namespaces []string
	workloads  []workload
	externals  []string
	at         time.Time
}

type (
	loadedMsg struct{ d *data }
	errMsg    struct{ err error }
	edgesMsg  struct {
		ns    string
		edges []policy.Edge
	}
	traceMsg struct{ res *policy.PathResult }
)

// picker is the modal flow for `t`: pick a source, a destination, a port.
type picker struct {
	step   int // 0 source, 1 destination, 2 port
	items  []string
	labels []string
	idx    int
	offset int
	filter textinput.Model
	src    string
	dst    string
}

// Model is the Bubble Tea model for the app.
type Model struct {
	fetch   func(context.Context) (*policy.Snapshot, error)
	ctxName string
	version string

	d       *data
	err     error
	loading bool
	spin    spinner.Model

	view       view
	pane       pane
	nsIdx      int
	listIdx    int
	listOffset int
	filter     textinput.Model
	filtering  bool
	showDenied bool
	help       bool
	yamlMode   bool
	pick       *picker

	edges     []policy.Edge
	edgesFor  string
	trace     *policy.PathResult
	showTrace bool

	detail viewport.Model
	width  int
	height int
}

// New builds the model; fetch produces a cluster-wide snapshot.
func New(fetch func(context.Context) (*policy.Snapshot, error), ctxName, version string) Model {
	f := textinput.New()
	f.Prompt = "/ "
	f.Placeholder = "filter"
	sp := spinner.New(spinner.WithSpinner(spinner.Dot), spinner.WithStyle(sAccent))
	return Model{fetch: fetch, ctxName: ctxName, version: version, filter: f, spin: sp, loading: true, pane: paneList}
}

// Run starts the app in the alternate screen with mouse support.
func Run(m Model) error {
	_, err := tea.NewProgram(m, tea.WithAltScreen(), tea.WithMouseCellMotion()).Run()
	return err
}

func (m Model) Init() tea.Cmd { return tea.Batch(m.load(), m.spin.Tick) }

/* ---------- commands ---------- */

func (m Model) load() tea.Cmd {
	fetch := m.fetch
	return func() tea.Msg {
		snap, err := fetch(context.Background())
		if err != nil {
			return errMsg{err}
		}
		views, cov := policy.Describe(snap)
		d := &data{snap: snap, policies: views, coverage: cov, findings: lint.Run(snap), externals: snap.ExternalTargets(), at: time.Now()}
		nsSet := map[string]bool{}
		byKey := map[string]*workload{}
		for _, w := range snap.Workloads() {
			nsSet[w.Namespace] = true
			ref := policy.WorkloadRef{Namespace: w.Namespace, Kind: w.Kind, Name: w.Name, Pods: len(w.Pods)}
			byKey[refKey(ref)] = &workload{ref: ref}
		}
		for _, p := range views {
			if p.Namespace != "" {
				nsSet[p.Namespace] = true
			}
			for _, s := range p.Selected {
				if w := byKey[refKey(s)]; w != nil {
					w.selectedBy = append(w.selectedBy, p.Key)
					w.I = w.I || p.IsolatesIngress
					w.E = w.E || p.IsolatesEgress
				}
			}
			for _, r := range append(append([]policy.RuleView{}, p.Ingress...), p.Egress...) {
				for _, peer := range r.Peers {
					for _, mm := range peer.Matches {
						if w := byKey[refKey(mm)]; w != nil && !contains(w.peerOf, p.Key) {
							w.peerOf = append(w.peerOf, p.Key)
						}
					}
				}
			}
		}
		for ns := range nsSet {
			d.namespaces = append(d.namespaces, ns)
		}
		sort.Strings(d.namespaces)
		for _, w := range byKey {
			d.workloads = append(d.workloads, *w)
		}
		sort.Slice(d.workloads, func(i, j int) bool { return refKey(d.workloads[i].ref) < refKey(d.workloads[j].ref) })
		return loadedMsg{d}
	}
}

func (m Model) computeEdges(ns string) tea.Cmd {
	snap := m.d.snap
	return func() tea.Msg {
		if ns == "" {
			edges, _, err := policy.Edges(snap, "", "", 0, false)
			if err != nil {
				return errMsg{err}
			}
			return edgesMsg{ns, edges}
		}
		seen := map[string]bool{}
		var out []policy.Edge
		for _, dir := range [2][2]string{{ns, ""}, {"", ns}} {
			edges, _, err := policy.Edges(snap, dir[0], dir[1], 0, false)
			if err != nil {
				return errMsg{err}
			}
			for _, e := range edges {
				k := refKey(e.From) + "|" + refKey(e.To)
				if !seen[k] {
					seen[k] = true
					out = append(out, e)
				}
			}
		}
		return edgesMsg{ns, out}
	}
}

func (m Model) runTrace(src, dst, port string) tea.Cmd {
	snap := m.d.snap
	return func() tea.Msg {
		res, err := policy.ExplainPath(snap, "", src, dst, port)
		if err != nil {
			return errMsg{err}
		}
		return traceMsg{res}
	}
}

/* ---------- helpers on state ---------- */

func refKey(w policy.WorkloadRef) string { return w.Namespace + "/" + w.Kind + "/" + w.Name }

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// selectedNS is "" for "all namespaces".
func (m Model) selectedNS() string {
	if m.d == nil || m.nsIdx == 0 || m.nsIdx-1 >= len(m.d.namespaces) {
		return ""
	}
	return m.d.namespaces[m.nsIdx-1]
}

func (m Model) q() string { return strings.ToLower(m.filter.Value()) }

func (m Model) visiblePolicies() []policy.PolicyView {
	if m.d == nil {
		return nil
	}
	ns, q := m.selectedNS(), m.q()
	out := []policy.PolicyView{}
	for _, p := range m.d.policies {
		// A namespace's view includes the policies defined in it, cluster-wide
		// ones, and policies elsewhere that name its workloads as peers.
		if ns != "" && p.Namespace != ns && p.Kind != "CiliumClusterwideNetworkPolicy" && !namesPeerIn(p, ns) {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(p.Key+" "+p.Selector), q) {
			continue
		}
		out = append(out, p)
	}
	return out
}

// namesPeerIn reports whether a rule of p resolves to a workload in ns.
func namesPeerIn(p policy.PolicyView, ns string) bool {
	for _, r := range append(append([]policy.RuleView{}, p.Ingress...), p.Egress...) {
		for _, peer := range r.Peers {
			for _, w := range peer.Matches {
				if w.Namespace == ns {
					return true
				}
			}
		}
	}
	return false
}

// role says what a policy is to the selected namespace.
func (m Model) role(p policy.PolicyView) string {
	ns := m.selectedNS()
	switch {
	case ns == "" || p.Namespace == ns:
		return ""
	case p.Kind == "CiliumClusterwideNetworkPolicy":
		return "cluster"
	}
	return "names peer"
}

func (m Model) visibleEdges() []policy.Edge {
	q := m.q()
	out := []policy.Edge{}
	for _, e := range m.edges {
		if e.Status == "deny" && !m.showDenied {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(refKey(e.From)+" "+refKey(e.To)+" "+e.Verdict+" "+e.Reason), q) {
			continue
		}
		out = append(out, e)
	}
	return out
}

func (m Model) visibleWorkloads() []workload {
	if m.d == nil {
		return nil
	}
	ns, q := m.selectedNS(), m.q()
	out := []workload{}
	for _, w := range m.d.workloads {
		if ns != "" && w.ref.Namespace != ns {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(refKey(w.ref)), q) {
			continue
		}
		out = append(out, w)
	}
	return out
}

func (m Model) listLen() int {
	switch m.view {
	case viewPolicies:
		return len(m.visiblePolicies())
	case viewWorkloads:
		return len(m.visibleWorkloads())
	}
	return len(m.visibleEdges())
}

func (m *Model) clampList() {
	n := m.listLen()
	if m.listIdx >= n {
		m.listIdx = n - 1
	}
	if m.listIdx < 0 {
		m.listIdx = 0
	}
	h := m.listRows()
	if m.listIdx < m.listOffset {
		m.listOffset = m.listIdx
	}
	if m.listIdx >= m.listOffset+h {
		m.listOffset = m.listIdx - h + 1
	}
	if m.listOffset < 0 {
		m.listOffset = 0
	}
}

// Geometry: header (headerRows) + list box (rows + title + column header +
// 2 borders) + detail box (rows + 2 borders) + status bar (1).
const headerRows = 6

func (m Model) listRows() int   { return max(3, (m.height-headerRows-7)*2/5) }
func (m Model) detailRows() int { return max(3, m.height-headerRows-7-m.listRows()) }
func (m Model) mainWidth() int  { return max(40, m.width-nsPaneWidth-4) }
func (m Model) listTop() int    { return headerRows + 3 }                // first list row on screen
func (m Model) detailTop() int  { return headerRows + m.listRows() + 4 } // first detail row
func (m Model) nsTop() int      { return headerRows + 2 }                // first namespace row

func (m *Model) resetSelection() {
	m.listIdx, m.listOffset, m.showTrace, m.yamlMode = 0, 0, false, false
}

/* ---------- update ---------- */

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.detail = viewport.New(m.mainWidth()-2, m.detailRows())
		m.clampList()
		m.refreshDetail()
		return m, nil
	case spinner.TickMsg:
		if !m.loading {
			return m, nil
		}
		var cmd tea.Cmd
		m.spin, cmd = m.spin.Update(msg)
		return m, cmd
	case loadedMsg:
		m.d, m.err, m.loading = msg.d, nil, false
		m.edgesFor = "?"
		m.clampList()
		m.refreshDetail()
		if m.view == viewConnections {
			return m, m.computeEdges(m.selectedNS())
		}
		return m, nil
	case errMsg:
		m.err, m.loading = msg.err, false
		return m, nil
	case edgesMsg:
		m.edges, m.edgesFor = msg.edges, msg.ns
		m.clampList()
		m.refreshDetail()
		return m, nil
	case traceMsg:
		m.trace, m.showTrace, m.yamlMode = msg.res, true, false
		m.pane = paneDetail
		m.refreshDetail()
		return m, nil
	case tea.MouseMsg:
		return m.handleMouse(msg)
	case tea.KeyMsg:
		return m.handleKey(msg)
	}
	return m, nil
}

func (m Model) handleMouse(msg tea.MouseMsg) (tea.Model, tea.Cmd) {
	if m.help || m.pick != nil {
		return m, nil
	}
	inNS := msg.X < nsPaneWidth+2
	inList := !inNS && msg.Y < m.detailTop()-1
	switch msg.Button {
	case tea.MouseButtonWheelUp, tea.MouseButtonWheelDown:
		delta := 3
		if msg.Button == tea.MouseButtonWheelUp {
			delta = -3
		}
		switch {
		case inNS:
			return m.moveNS(delta / 3)
		case inList:
			m.listIdx += delta
			m.showTrace, m.yamlMode = false, false
			m.clampList()
			m.refreshDetail()
		default:
			if delta > 0 {
				m.detail.ScrollDown(3)
			} else {
				m.detail.ScrollUp(3)
			}
		}
		return m, nil
	case tea.MouseButtonLeft:
		if msg.Action != tea.MouseActionPress {
			return m, nil
		}
		switch {
		case inNS:
			m.pane = paneNS
			if i := msg.Y - m.nsTop(); i >= 0 && m.d != nil && i <= len(m.d.namespaces) && i != m.nsIdx {
				return m.moveNS(i - m.nsIdx)
			}
		case inList:
			m.pane = paneList
			if msg.Y == headerRows+1 { // view tabs on the title line
				for i, x := range m.tabStarts() {
					if msg.X-nsPaneWidth-3 >= x {
						return m.switchView(view(i))
					}
				}
			}
			if i := m.listOffset + msg.Y - m.listTop(); i >= 0 && i < m.listLen() {
				m.listIdx = i
				m.showTrace, m.yamlMode = false, false
				m.clampList()
				m.refreshDetail()
			}
		default:
			m.pane = paneDetail
		}
	}
	return m, nil
}

func (m Model) moveNS(delta int) (tea.Model, tea.Cmd) {
	n := 1
	if m.d != nil {
		n = len(m.d.namespaces) + 1
	}
	m.nsIdx = ((m.nsIdx+delta)%n + n) % n
	m.resetSelection()
	m.clampList()
	m.refreshDetail()
	if m.view == viewConnections && m.d != nil {
		return m, m.computeEdges(m.selectedNS())
	}
	return m, nil
}

func (m Model) switchView(v view) (tea.Model, tea.Cmd) {
	m.view = v
	m.resetSelection()
	m.pane = paneList
	m.clampList()
	m.refreshDetail()
	if m.view == viewConnections && m.d != nil && m.edgesFor != m.selectedNS() {
		return m, m.computeEdges(m.selectedNS())
	}
	return m, nil
}

func (m Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()
	if m.help {
		m.help = false
		return m, nil
	}
	if m.pick != nil {
		return m.handlePicker(msg)
	}
	if m.filtering {
		switch key {
		case "enter", "esc":
			m.filtering = false
			m.filter.Blur()
			if key == "esc" {
				m.filter.SetValue("")
			}
			m.listIdx = 0
			m.clampList()
			m.refreshDetail()
			return m, nil
		}
		var cmd tea.Cmd
		m.filter, cmd = m.filter.Update(msg)
		m.listIdx = 0
		m.clampList()
		m.refreshDetail()
		return m, cmd
	}

	switch key {
	case "q", "ctrl+c":
		return m, tea.Quit
	case "?":
		m.help = true
		return m, nil
	case "r":
		m.loading = true
		return m, tea.Batch(m.load(), m.spin.Tick)
	case "/":
		m.filtering = true
		m.pane = paneList
		return m, m.filter.Focus()
	case "esc":
		m.filter.SetValue("")
		m.showTrace, m.yamlMode = false, false
		m.clampList()
		m.refreshDetail()
		return m, nil
	case "tab":
		m.pane = (m.pane + 1) % 3
		return m, nil
	case "1", "2", "3":
		return m.switchView(view(key[0] - '1'))
	case "d":
		m.showDenied = !m.showDenied
		m.clampList()
		m.refreshDetail()
		return m, nil
	case "y":
		if m.view == viewPolicies {
			m.yamlMode, m.showTrace = !m.yamlMode, false
			m.pane = paneDetail
			m.refreshDetail()
		}
		return m, nil
	case "t":
		if m.d != nil {
			m.pick = m.newPicker()
			return m, m.pick.filter.Focus()
		}
		return m, nil
	}

	switch m.pane {
	case paneNS:
		switch key {
		case "up", "k":
			return m.moveNS(-1)
		case "down", "j":
			return m.moveNS(1)
		}
		return m, nil
	case paneList:
		switch key {
		case "up", "k":
			m.listIdx--
		case "down", "j":
			m.listIdx++
		case "pgup":
			m.listIdx -= m.listRows()
		case "pgdown":
			m.listIdx += m.listRows()
		case "home", "g":
			m.listIdx = 0
		case "end", "G":
			m.listIdx = m.listLen() - 1
		case "enter":
			return m.enter()
		default:
			return m, nil
		}
		m.showTrace, m.yamlMode = false, false
		m.clampList()
		m.refreshDetail()
		return m, nil
	case paneDetail:
		var cmd tea.Cmd
		m.detail, cmd = m.detail.Update(msg)
		return m, cmd
	}
	return m, nil
}

// enter acts on the selected row: trace a connection, open a policy, or
// jump from a workload to its connections.
func (m Model) enter() (tea.Model, tea.Cmd) {
	switch m.view {
	case viewConnections:
		if es := m.visibleEdges(); m.listIdx < len(es) {
			e := es[m.listIdx]
			return m, m.runTrace(refKey(e.From), refKey(e.To), "")
		}
	case viewWorkloads:
		if ws := m.visibleWorkloads(); m.listIdx < len(ws) {
			m.filter.SetValue(refKey(ws[m.listIdx].ref))
			return m.switchView(viewConnections)
		}
	}
	m.pane = paneDetail
	return m, nil
}

/* ---------- trace picker ---------- */

func (m Model) newPicker() *picker {
	f := textinput.New()
	f.Prompt = "/ "
	f.Placeholder = "type to filter"
	p := &picker{filter: f}
	m.fillPicker(p)
	return p
}

func (m Model) fillPicker(p *picker) {
	p.items, p.labels, p.idx, p.offset = nil, nil, 0, 0
	switch p.step {
	case 0:
		for _, w := range m.d.workloads {
			p.items = append(p.items, refKey(w.ref))
			p.labels = append(p.labels, fmt.Sprintf("%-50s %s", refKey(w.ref), sMuted.Render(fmt.Sprintf("%d pods", w.ref.Pods))))
		}
	case 1:
		for _, s := range m.d.snap.Services {
			ports := []string{}
			for _, sp := range s.Spec.Ports {
				ports = append(ports, fmt.Sprint(sp.Port))
			}
			key := s.Namespace + "/" + s.Name
			p.items = append(p.items, key)
			p.labels = append(p.labels, fmt.Sprintf("%-50s %s", key, sMuted.Render("Service · ports "+strings.Join(ports, ","))))
		}
		for _, w := range m.d.workloads {
			p.items = append(p.items, refKey(w.ref))
			p.labels = append(p.labels, fmt.Sprintf("%-50s %s", refKey(w.ref), sMuted.Render("workload")))
		}
		p.items = append(p.items, "internet")
		p.labels = append(p.labels, fmt.Sprintf("%-50s %s", "internet", sMuted.Render("any host outside the cluster")))
		for _, x := range m.d.externals {
			p.items = append(p.items, x)
			p.labels = append(p.labels, fmt.Sprintf("%-50s %s", x, sMuted.Render("external, named in a policy")))
		}
	}
}

func (p *picker) visible() ([]string, []string) {
	q := strings.ToLower(p.filter.Value())
	items, labels := []string{}, []string{}
	for i, it := range p.items {
		if q == "" || strings.Contains(strings.ToLower(it), q) {
			items = append(items, it)
			labels = append(labels, p.labels[i])
		}
	}
	return items, labels
}

func (m Model) handlePicker(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	p := m.pick
	items, _ := p.visible()
	switch msg.String() {
	case "esc":
		m.pick = nil
		return m, nil
	case "up", "ctrl+p":
		p.idx = max(0, p.idx-1)
	case "down", "ctrl+n":
		p.idx = min(len(items)-1, p.idx+1)
	case "enter":
		switch p.step {
		case 0, 1:
			if p.idx >= len(items) {
				return m, nil
			}
			if p.step == 0 {
				p.src = items[p.idx]
			} else {
				p.dst = items[p.idx]
			}
			p.step++
			p.filter.SetValue("")
			p.filter.Placeholder = "port (optional)"
			if p.step == 2 {
				p.filter.Placeholder = "port number or name, enter to skip"
			}
			m.fillPicker(p)
			return m, nil
		default:
			src, dst, port := p.src, p.dst, strings.TrimSpace(p.filter.Value())
			m.pick = nil
			return m, m.runTrace(src, dst, port)
		}
	default:
		var cmd tea.Cmd
		p.filter, cmd = p.filter.Update(msg)
		p.idx = 0
		return m, cmd
	}
	if p.idx < p.offset {
		p.offset = p.idx
	}
	if p.idx >= p.offset+12 {
		p.offset = p.idx - 11
	}
	return m, nil
}

/* ---------- rendering ---------- */

var (
	cAccent = lipgloss.AdaptiveColor{Light: "#3b5bdb", Dark: "#8fa6ff"}
	cMuted  = lipgloss.AdaptiveColor{Light: "#5b6370", Dark: "#a8adb5"}
	cOK     = lipgloss.AdaptiveColor{Light: "#137a3a", Dark: "#5ee08f"}
	cWarn   = lipgloss.AdaptiveColor{Light: "#9a5a00", Dark: "#ffc857"}
	cFail   = lipgloss.AdaptiveColor{Light: "#c22424", Dark: "#ff7b7b"}
	cTeal   = lipgloss.AdaptiveColor{Light: "#0f766e", Dark: "#5fd3c7"}
	cBorder = lipgloss.AdaptiveColor{Light: "#cfd3d9", Dark: "#444444"}

	sTitle   = lipgloss.NewStyle().Bold(true)
	sMuted   = lipgloss.NewStyle().Foreground(cMuted)
	sAccent  = lipgloss.NewStyle().Foreground(cAccent).Bold(true)
	sOK      = lipgloss.NewStyle().Foreground(cOK).Bold(true)
	sWarn    = lipgloss.NewStyle().Foreground(cWarn).Bold(true)
	sFail    = lipgloss.NewStyle().Foreground(cFail).Bold(true)
	sTeal    = lipgloss.NewStyle().Foreground(cTeal).Bold(true)
	sSel     = lipgloss.NewStyle().Background(cAccent).Foreground(lipgloss.Color("#ffffff")).Bold(true)
	sHead    = lipgloss.NewStyle().Foreground(cMuted).Bold(true)
	sPane    = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(cBorder).Padding(0, 1)
	sActive  = sPane.BorderForeground(cAccent)
	sBox     = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(cBorder).Padding(0, 1)
	sBoxDeny = sBox.BorderForeground(cFail)
	sBoxSel  = sBox.BorderForeground(cAccent)
	sModal   = lipgloss.NewStyle().Border(lipgloss.DoubleBorder()).BorderForeground(cAccent).Padding(1, 2)
)

func (m Model) View() string {
	if m.width == 0 {
		return "loading…"
	}
	body := lipgloss.JoinHorizontal(lipgloss.Top, m.renderNS(), lipgloss.JoinVertical(lipgloss.Left, m.renderList(), m.renderDetail()))
	screen := lipgloss.JoinVertical(lipgloss.Left, m.renderHeader(), body, m.renderStatus())
	switch {
	case m.help:
		return m.overlay(m.renderHelp())
	case m.pick != nil:
		return m.overlay(m.renderPicker())
	}
	return screen
}

func (m Model) overlay(box string) string {
	return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, box, lipgloss.WithWhitespaceChars(" "))
}

// logo is the k9s-style banner shown top-right when the terminal is wide
// enough: the figlet "standard" font, assembled glyph by glyph so the rows
// always line up.
var logo = renderLogo("netpol-map")

// figletStandard holds the glyphs the logo needs; every row of a glyph has
// the same width.
var figletStandard = map[rune][6]string{
	'n': {"       ", " _ __  ", "| '_ \\ ", "| | | |", "|_| |_|", "       "},
	'e': {"       ", "  ___  ", " / _ \\ ", "|  __/ ", " \\___| ", "       "},
	't': {" _   ", "| |_ ", "| __|", "| |_ ", " \\__|", "     "},
	'p': {"       ", " _ __  ", "| '_ \\ ", "| |_) |", "| .__/ ", "|_|    "},
	'o': {"       ", "  ___  ", " / _ \\ ", "| (_) |", " \\___/ ", "       "},
	'l': {" _ ", "| |", "| |", "| |", "|_|", "   "},
	'-': {"       ", "       ", " _____ ", "|_____|", "       ", "       "},
	'm': {"           ", " _ __ ___  ", "| '_ ` _ \\ ", "| | | | | |", "|_| |_| |_|", "           "},
	'a': {"       ", "  __ _ ", " / _` |", "| (_| |", " \\__,_|", "       "},
}

func renderLogo(text string) []string {
	rows := make([]string, 6)
	for _, r := range text {
		g, ok := figletStandard[r]
		if !ok {
			continue
		}
		for i := range rows {
			rows[i] += g[i]
		}
	}
	return rows
}

func (m Model) renderHeader() string {
	k := func(s string) string { return sMuted.Render(fmt.Sprintf(" %-11s", s)) }
	lines := []string{k("context") + sTitle.Render(m.ctxName)}
	switch {
	case m.err != nil:
		lines = append(lines, k("error")+sFail.Render(m.err.Error()))
	case m.d != nil:
		c := m.d.coverage
		lines = append(lines,
			k("cluster")+fmt.Sprintf("%d namespaces · %d pods · %d policies", len(m.d.namespaces), len(m.d.snap.Pods), len(m.d.policies)),
			k("isolated")+sAccent.Render(fmt.Sprintf("%d/%d ingress · %d/%d egress", c.IsolatedIngress, c.Workloads, c.IsolatedEgress, c.Workloads)),
			k("untouched")+sWarn.Render(fmt.Sprintf("%d workloads with no policy (all traffic allowed)", len(c.Unprotected))),
			k("refreshed")+m.d.at.Format("15:04:05"))
		if len(m.d.snap.Unevaluated) > 0 { // the header has a fixed height, so this rides on the cluster line
			lines[len(lines)-4] += "   " + sFail.Render("not evaluated, verdicts may be wrong: "+strings.Join(m.d.snap.Unevaluated, ", "))
		}
	default:
		lines = append(lines, k("")+m.spin.View()+" reading the cluster…")
	}
	for len(lines) < headerRows {
		lines = append(lines, "")
	}
	logoW := lipgloss.Width(logo[0]) + 2
	if m.width < 70+logoW {
		return lipgloss.NewStyle().Width(m.width).Render(strings.Join(lines[:headerRows], "\n"))
	}
	left := lipgloss.NewStyle().Width(m.width - logoW).Render(strings.Join(lines[:headerRows], "\n"))
	return lipgloss.JoinHorizontal(lipgloss.Top, left, sAccent.Render(strings.Join(logo, "\n")))
}

func (m Model) renderStatus() string {
	left := ""
	if m.loading {
		left = m.spin.View() + " reading the cluster…"
	}
	mid := ""
	if m.d != nil {
		total := map[view]int{viewPolicies: len(m.d.policies), viewConnections: len(m.edges), viewWorkloads: len(m.d.workloads)}[m.view]
		mid = fmt.Sprintf("%d of %d shown", m.listLen(), total)
		if m.filter.Value() != "" {
			mid += sMuted.Render("  filter: ") + m.filter.Value()
		}
		if m.view == viewConnections && !m.showDenied {
			mid += sMuted.Render("  denied hidden (d)")
		}
	}
	right := sMuted.Render("? help  ·  t trace  ·  y yaml  ·  q quit  ·  " + m.version)
	gap1 := max(1, (m.width-lipgloss.Width(left)-lipgloss.Width(mid)-lipgloss.Width(right))/2)
	return " " + left + strings.Repeat(" ", gap1) + mid + strings.Repeat(" ", max(1, m.width-1-lipgloss.Width(left)-gap1-lipgloss.Width(mid)-lipgloss.Width(right))) + right
}

func (m Model) renderNS() string {
	h := m.listRows() + 2 + m.detailRows() + 2
	lines := []string{sHead.Render("NAMESPACES")}
	items := []string{"all namespaces"}
	if m.d != nil {
		items = append(items, m.d.namespaces...)
	}
	for i, it := range items {
		label := it
		if m.d != nil && i > 0 {
			n := 0
			for _, p := range m.d.policies {
				if p.Namespace == it {
					n++
				}
			}
			if n > 0 {
				label = fmt.Sprintf("%-*s%d", nsPaneWidth-4-len(fmt.Sprint(n)), trunc(it, nsPaneWidth-6), n)
			}
		}
		label = trunc(label, nsPaneWidth-2)
		if i == m.nsIdx {
			lines = append(lines, sSel.Render(fmt.Sprintf("%-*s", nsPaneWidth-2, label)))
		} else {
			lines = append(lines, label)
		}
	}
	style := sPane
	if m.pane == paneNS {
		style = sActive
	}
	return style.Width(nsPaneWidth).Height(h).Render(strings.Join(lines, "\n"))
}

var tabNames = []string{"1 Policies", "2 Connections", "3 Workloads"}

// tabStarts returns the x offset of each tab inside the list title, for
// mouse clicks.
func (m Model) tabStarts() []int {
	out, x := []int{}, 0
	for _, n := range tabNames {
		out = append(out, x)
		x += len(n) + 3
	}
	return out
}

func (m Model) renderList() string {
	w := m.mainWidth()
	title := []string{}
	for i, n := range tabNames {
		if m.view == view(i) {
			title = append(title, sAccent.Render("["+n+"]"))
		} else {
			title = append(title, sMuted.Render(" "+n+" "))
		}
	}
	line := strings.Join(title, " ")
	if m.filtering || m.filter.Value() != "" {
		line += "   " + m.filter.View()
	}
	lines := []string{line}
	h := m.listRows()
	switch {
	case m.loading && m.d == nil:
		lines = append(lines, "", sMuted.Render("loading…"))
	case m.view == viewPolicies:
		lines = append(lines, sHead.Render(fmt.Sprintf("%-5s %-38s %-10s %-5s %-16s %-28s %5s %9s", "KIND", "NAME", "ROLE", "ISOL", "FINDINGS", "SELECTS", "WL", "IN/OUT")))
		ps := m.visiblePolicies()
		if len(ps) == 0 {
			lines = append(lines, sMuted.Render("no policy is defined in this namespace and none elsewhere names its workloads: all traffic is allowed"))
		}
		for i := m.listOffset; i < len(ps) && i < m.listOffset+h; i++ {
			lines = append(lines, m.policyLine(ps[i], i == m.listIdx, w-2))
		}
	case m.view == viewWorkloads:
		lines = append(lines, sHead.Render(fmt.Sprintf("%-12s %-36s %5s %-5s %-9s %s", "KIND", "NAME", "PODS", "ISOL", "POLICIES", "NAMED AS PEER BY")))
		ws := m.visibleWorkloads()
		if len(ws) == 0 {
			lines = append(lines, sMuted.Render("no workloads here"))
		}
		for i := m.listOffset; i < len(ws) && i < m.listOffset+h; i++ {
			lines = append(lines, m.workloadLine(ws[i], i == m.listIdx, w-2))
		}
	default:
		lines = append(lines, sHead.Render(fmt.Sprintf("%-32s %-3s %-32s %-14s %s", "SOURCE", "", "DESTINATION", "VERDICT", "WHY")))
		if m.edgesFor != m.selectedNS() {
			lines = append(lines, sMuted.Render("evaluating…"))
			break
		}
		es := m.visibleEdges()
		if len(es) == 0 {
			lines = append(lines, sMuted.Render("no notable connections"+map[bool]string{true: "", false: " (press d to include denied)"}[m.showDenied]))
		}
		for i := m.listOffset; i < len(es) && i < m.listOffset+h; i++ {
			lines = append(lines, m.edgeLine(es[i], i == m.listIdx, w-2))
		}
	}
	style := sPane
	if m.pane == paneList {
		style = sActive
	}
	return style.Width(w).Height(h + 2).Render(strings.Join(lines, "\n"))
}

var kindTag = map[string]string{"NetworkPolicy": "NP", "CiliumNetworkPolicy": "CNP", "CiliumClusterwideNetworkPolicy": "CCNP"}

func (m Model) policyLine(p policy.PolicyView, sel bool, w int) string {
	name := p.Name
	if p.Namespace != "" {
		name = p.Namespace + "/" + p.Name
	}
	iso := ""
	if p.IsolatesIngress {
		iso += "I "
	}
	if p.IsolatesEgress {
		iso += "E"
	}
	codes := []string{}
	for _, f := range m.findingsFor(p) {
		codes = append(codes, f.Code)
	}
	cells := []string{
		fmt.Sprintf("%-5s", kindTag[p.Kind]), fmt.Sprintf("%-38s", trunc(name, 38)), fmt.Sprintf("%-10s", m.role(p)), fmt.Sprintf("%-5s", iso),
		fmt.Sprintf("%-16s", trunc(strings.Join(codes, " "), 16)), fmt.Sprintf("%-28s", trunc(p.Selector, 28)),
		fmt.Sprintf("%5d", len(p.Selected)), fmt.Sprintf("%4d/%-4d", len(p.Ingress), len(p.Egress)),
	}
	if sel {
		return sSel.Render(fmt.Sprintf("%-*s", w, trunc(strings.Join(cells, " "), w)))
	}
	kindStyle := sTeal
	if p.Kind == "NetworkPolicy" {
		kindStyle = sAccent
	}
	return strings.Join([]string{kindStyle.Render(cells[0]), cells[1], sMuted.Render(cells[2]), sFail.Render(cells[3]), sWarn.Render(cells[4]), sMuted.Render(cells[5]), cells[6], cells[7]}, " ")
}

func (m Model) workloadLine(wl workload, sel bool, w int) string {
	iso := ""
	if wl.I {
		iso += "I "
	}
	if wl.E {
		iso += "E"
	}
	peers := strings.Join(shortKeys(wl.peerOf, 3), ", ")
	cells := []string{
		fmt.Sprintf("%-12s", trunc(wl.ref.Kind, 12)), fmt.Sprintf("%-36s", trunc(wl.ref.Namespace+"/"+wl.ref.Name, 36)),
		fmt.Sprintf("%5d", wl.ref.Pods), fmt.Sprintf("%-5s", iso), fmt.Sprintf("%-9d", len(wl.selectedBy)), peers,
	}
	line := trunc(strings.Join(cells, " "), w)
	if sel {
		return sSel.Render(fmt.Sprintf("%-*s", w, line))
	}
	isoStyle := sFail
	if iso == "" {
		isoStyle = sWarn
		cells[3] = fmt.Sprintf("%-5s", "open")
	}
	return strings.Join([]string{sMuted.Render(cells[0]), cells[1], cells[2], isoStyle.Render(cells[3]), cells[4], sMuted.Render(trunc(peers, max(10, w-74)))}, " ")
}

func (m Model) edgeLine(e policy.Edge, sel bool, w int) string {
	st := sOK
	switch e.Status {
	case "deny":
		st = sFail
	case "partial", "unknown":
		st = sWarn
	}
	arrow := map[string]string{"allow": "──▶", "deny": "──╳", "partial": "─?▶", "unknown": "─?▶"}[e.Status]
	cells := []string{fmt.Sprintf("%-32s", trunc(refKey(e.From), 32)), arrow, fmt.Sprintf("%-32s", trunc(refKey(e.To), 32)), fmt.Sprintf("%-14s", e.Verdict), e.Reason}
	line := trunc(strings.Join(cells, " "), w)
	if sel {
		return sSel.Render(fmt.Sprintf("%-*s", w, line))
	}
	return strings.Join([]string{cells[0], st.Render(arrow), cells[2], st.Render(cells[3]), sMuted.Render(trunc(e.Reason, max(10, w-86)))}, " ")
}

func shortKeys(keys []string, max int) []string {
	out := []string{}
	for i, k := range keys {
		if i == max {
			out = append(out, fmt.Sprintf("+%d", len(keys)-max))
			break
		}
		out = append(out, strings.TrimPrefix(strings.TrimPrefix(strings.TrimPrefix(k, "NetworkPolicy/"), "CiliumNetworkPolicy/"), "CiliumClusterwideNetworkPolicy/"))
	}
	return out
}

func (m Model) findingsFor(p policy.PolicyView) []lint.Finding {
	if m.d == nil {
		return nil
	}
	key := p.Name
	if p.Namespace != "" {
		key = p.Namespace + "/" + p.Name
	}
	out := []lint.Finding{}
	for _, f := range m.d.findings {
		for _, s := range strings.FieldsFunc(f.Subject, func(r rune) bool { return r == ' ' || r == ',' || r == '+' }) {
			if s == key {
				out = append(out, f)
			}
		}
	}
	return out
}

func (m *Model) refreshDetail() {
	m.detail.SetContent(m.detailContent())
	m.detail.GotoTop()
}

func (m Model) renderDetail() string {
	style := sPane
	if m.pane == paneDetail {
		style = sActive
	}
	return style.Width(m.mainWidth()).Height(m.detailRows()).Render(m.detail.View())
}

func (m Model) detailContent() string {
	if m.d == nil {
		return ""
	}
	w := m.mainWidth() - 4
	if m.showTrace && m.trace != nil {
		return renderTrace(m.trace, w)
	}
	switch m.view {
	case viewConnections:
		es := m.visibleEdges()
		if m.listIdx >= len(es) {
			return sMuted.Render("select a connection; enter traces it layer by layer, t traces any pair")
		}
		e := es[m.listIdx]
		return fmt.Sprintf("%s → %s\n%s  %s\n\n%s", sTitle.Render(refKey(e.From)), sTitle.Render(refKey(e.To)),
			verdictStyle(e.Status).Render(e.Verdict), e.Reason, sMuted.Render("enter: trace this connection layer by layer"))
	case viewWorkloads:
		ws := m.visibleWorkloads()
		if m.listIdx >= len(ws) {
			return ""
		}
		return m.renderWorkload(ws[m.listIdx])
	}
	ps := m.visiblePolicies()
	if m.listIdx >= len(ps) {
		if len(m.d.coverage.Unprotected) > 0 {
			names := []string{}
			for _, u := range m.d.coverage.Unprotected {
				names = append(names, refKey(u))
			}
			return sWarn.Render(fmt.Sprintf("%d workloads touched by no policy (all traffic allowed):", len(names))) + "\n" + strings.Join(names, "\n")
		}
		return ""
	}
	if m.yamlMode {
		return m.renderYAML(ps[m.listIdx])
	}
	return renderPolicy(ps[m.listIdx], m.findingsFor(ps[m.listIdx]), w)
}

func (m Model) renderWorkload(wl workload) string {
	lines := []string{sTitle.Render(refKey(wl.ref)) + sMuted.Render(fmt.Sprintf("  %d pods", wl.ref.Pods))}
	switch {
	case wl.I && wl.E:
		lines = append(lines, sFail.Render("isolated for ingress and egress: only the rules below allow traffic"))
	case wl.I:
		lines = append(lines, sFail.Render("isolated for ingress")+sMuted.Render(" · egress not restricted"))
	case wl.E:
		lines = append(lines, sFail.Render("isolated for egress")+sMuted.Render(" · ingress not restricted"))
	default:
		lines = append(lines, sWarn.Render("no policy selects it: all traffic allowed"))
	}
	lines = append(lines, "", sHead.Render("SELECTED BY"))
	if len(wl.selectedBy) == 0 {
		lines = append(lines, sMuted.Render("  none"))
	}
	for _, k := range wl.selectedBy {
		lines = append(lines, "  "+k)
	}
	lines = append(lines, "", sHead.Render("NAMED AS A PEER BY"))
	if len(wl.peerOf) == 0 {
		lines = append(lines, sMuted.Render("  none"))
	}
	for _, k := range wl.peerOf {
		lines = append(lines, "  "+k)
	}
	lines = append(lines, "", sMuted.Render("enter: show this workload's connections"))
	return strings.Join(lines, "\n")
}

/* ---------- yaml ---------- */

var yamlKey = regexp.MustCompile(`^(\s*(?:- )?)([A-Za-z0-9_.\-/]+)(:)(.*)$`)

func (m Model) renderYAML(p policy.PolicyView) string {
	var obj any
	switch p.Kind {
	case "NetworkPolicy":
		for _, np := range m.d.snap.Policies {
			if np.Namespace == p.Namespace && np.Name == p.Name {
				np.ManagedFields = nil
				np.APIVersion, np.Kind = "networking.k8s.io/v1", "NetworkPolicy"
				obj = np
			}
		}
	default:
		for _, u := range append(append([]policyObj{}, toObjs(m.d.snap.CiliumNamespacePolicies)...), toObjs(m.d.snap.CiliumClusterPolicies)...) {
			if u.ns == p.Namespace && u.name == p.Name && u.kind == p.Kind {
				obj = u.obj
			}
		}
	}
	if obj == nil {
		return sMuted.Render("manifest not found in the snapshot")
	}
	raw, err := yaml.Marshal(obj)
	if err != nil {
		return sFail.Render(err.Error())
	}
	out := []string{}
	for _, line := range strings.Split(strings.TrimRight(string(raw), "\n"), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			out = append(out, sMuted.Render(line))
			continue
		}
		if mm := yamlKey.FindStringSubmatch(line); mm != nil {
			out = append(out, mm[1]+sAccent.Render(mm[2])+mm[3]+mm[4])
			continue
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

type policyObj struct {
	ns, name, kind string
	obj            map[string]any
}

func toObjs(us []unstructured.Unstructured) []policyObj {
	out := []policyObj{}
	for _, u := range us {
		o := map[string]any{}
		for k, v := range u.UnstructuredContent() {
			o[k] = v
		}
		if md, ok := o["metadata"].(map[string]any); ok {
			md2 := map[string]any{}
			for k, v := range md {
				if k != "managedFields" {
					md2[k] = v
				}
			}
			o["metadata"] = md2
		}
		out = append(out, policyObj{ns: u.GetNamespace(), name: u.GetName(), kind: u.GetKind(), obj: o})
	}
	return out
}

/* ---------- policy detail ---------- */

func verdictStyle(status string) lipgloss.Style {
	switch status {
	case "deny":
		return sFail
	case "partial", "unknown":
		return sWarn
	}
	return sOK
}

// renderPolicy draws the editor layout: allowed sources, the selected
// workloads, allowed destinations, with one arrow per rule carrying its ports.
func renderPolicy(p policy.PolicyView, findings []lint.Finding, w int) string {
	const aw = 18
	narrow := w < 100
	colW := (w - 2*aw - 6) / 3
	if narrow {
		colW = w - 2
	}
	var out []string
	name := p.Name
	if p.Namespace != "" {
		name = p.Namespace + "/" + p.Name
	}
	iso := func(dir string, isolated bool) string {
		if isolated {
			return sFail.Render(dir + ": default deny")
		}
		return sOK.Render(dir + ": default allow")
	}
	out = append(out, sTitle.Render(p.Kind+" "+name)+"  "+sMuted.Render("selects "+p.Selector)+"   "+iso("ingress", p.IsolatesIngress)+" · "+iso("egress", p.IsolatesEgress))
	if p.Rejected != "" {
		out = append(out, sFail.Render("NOT ENFORCED")+" Cilium rejected this policy: "+p.Rejected)
	}
	for _, f := range findings {
		out = append(out, sWarn.Render(f.Code)+" "+f.Message+sMuted.Render("  "+f.Hint))
	}
	out = append(out, "", sTitle.Render("What this policy does"))
	out = append(out, sentences(p)...)
	out = append(out, "")

	center := []string{sAccent.Render(name)}
	for i, s := range p.Selected {
		if i == 10 {
			center = append(center, sMuted.Render(fmt.Sprintf("+%d more", len(p.Selected)-10)))
			break
		}
		center = append(center, fmt.Sprintf("%s/%s  %s", s.Kind, s.Name, sMuted.Render(fmt.Sprintf("%d pods", s.Pods))))
	}
	if len(p.Selected) == 0 {
		center = append(center, sMuted.Render("selects no running workload"))
	}
	centerBox := sBoxSel.Width(colW).Render(strings.Join(center, "\n"))

	// A rejected policy isolates nothing, but its rules are what will apply
	// once Cilium accepts it, so they are still drawn.
	rejected := p.Rejected != ""
	leftBoxes, leftRules := ruleBoxes(p.Ingress, p.IsolatesIngress || (rejected && len(p.Ingress) > 0), "ingress", colW)
	rightBoxes, rightRules := ruleBoxes(p.Egress, p.IsolatesEgress || (rejected && len(p.Egress) > 0), "egress", colW)
	if narrow {
		out = append(out, sHead.Render("ALLOWED SOURCES"), lipgloss.JoinVertical(lipgloss.Left, leftBoxes...),
			sOK.Render("   ▼ into"), sHead.Render("SELECTED"), centerBox,
			sOK.Render("   ▼ out to"), sHead.Render("ALLOWED DESTINATIONS"), lipgloss.JoinVertical(lipgloss.Left, rightBoxes...))
		return strings.Join(out, "\n")
	}
	head := lipgloss.JoinHorizontal(lipgloss.Top,
		sHead.Width(colW+2).Render("ALLOWED SOURCES"), strings.Repeat(" ", aw),
		sHead.Width(colW+2).Render("SELECTED"), strings.Repeat(" ", aw),
		sHead.Width(colW+2).Render("ALLOWED DESTINATIONS"))
	body := lipgloss.JoinHorizontal(lipgloss.Top,
		lipgloss.JoinVertical(lipgloss.Left, leftBoxes...), arrowColumn(leftBoxes, leftRules, aw),
		centerBox, arrowColumn(rightBoxes, rightRules, aw),
		lipgloss.JoinVertical(lipgloss.Left, rightBoxes...))
	out = append(out, head, body)
	return strings.Join(out, "\n")
}

// portText shortens a port list for display: TCP is the default and is
// dropped, "any" becomes "any port".
func portText(ports []string) string {
	if len(ports) == 1 && ports[0] == "any" {
		return "any port"
	}
	out := []string{}
	for _, p := range ports {
		out = append(out, strings.TrimSuffix(p, "/TCP"))
	}
	return strings.Join(out, ", ")
}

// sentences spells out every connection a policy creates, one per line,
// resolved to workloads where possible.
func sentences(p policy.PolicyView) []string {
	sel := shortNames(p.Selected, 3)
	if len(p.Selected) == 0 {
		sel = "nothing (selector matches no workload)"
	}
	verb := func(r policy.RuleView) string {
		if r.Deny {
			return sFail.Render("✗ denies ")
		}
		return sOK.Render("✓ allows ")
	}
	out := []string{}
	for _, r := range p.Ingress {
		for _, peer := range r.Peers {
			out = append(out, fmt.Sprintf("  %s%s  →  %s  on %s", verb(r), peerText(peer), sAccent.Render(sel), portText(r.Ports)))
		}
	}
	for _, r := range p.Egress {
		for _, peer := range r.Peers {
			out = append(out, fmt.Sprintf("  %s%s  →  %s  on %s", verb(r), sAccent.Render(sel), peerText(peer), portText(r.Ports)))
		}
	}
	if p.IsolatesIngress {
		out = append(out, "  "+sFail.Render("✗ denies ")+"everything else  →  "+sAccent.Render(sel))
	}
	if p.IsolatesEgress {
		out = append(out, "  "+sFail.Render("✗ denies ")+sAccent.Render(sel)+"  →  everything else")
	}
	if len(out) == 0 {
		out = append(out, sMuted.Render("  nothing: it neither isolates nor allows"))
	}
	return out
}

func peerText(peer policy.PeerView) string {
	if len(peer.Matches) > 0 {
		return shortNames(peer.Matches, 3)
	}
	if peer.Matches != nil {
		return peer.Label + sMuted.Render(" (matches no workload)")
	}
	return peer.Label
}

func shortNames(ws []policy.WorkloadRef, max int) string {
	names := []string{}
	for i, w := range ws {
		if i == max {
			names = append(names, fmt.Sprintf("+%d more", len(ws)-max))
			break
		}
		names = append(names, w.Namespace+"/"+w.Name)
	}
	return strings.Join(names, ", ")
}

// arrowColumn draws one arrow per rule box, on the box's middle line, with
// the rule's ports on the shaft, so each line reads box → ports → target.
func arrowColumn(boxes []string, rules []policy.RuleView, width int) string {
	lines := []string{}
	for i, b := range boxes {
		h := lipgloss.Height(b)
		for l := range h {
			if l != h/2 || i >= len(rules) {
				lines = append(lines, "")
				continue
			}
			label := portText(rules[i].Ports)
			if label == "any port" {
				label = ""
			} else {
				label = ":" + label
			}
			label = trunc(label, width-6)
			shaft := strings.Repeat("─", max(1, (width-3-lipgloss.Width(label))/2))
			if rules[i].Deny {
				lines = append(lines, sFail.Render(shaft+label+shaft+"╳"))
			} else {
				lines = append(lines, sOK.Render(shaft+label+shaft+"▶"))
			}
		}
	}
	return lipgloss.NewStyle().Width(width).Render(strings.Join(lines, "\n"))
}

// ruleBoxes renders one box per rule; the returned rules slice is aligned
// with the boxes so arrows can be labelled (a placeholder box has no rule).
func ruleBoxes(rules []policy.RuleView, isolated bool, dir string, colW int) ([]string, []policy.RuleView) {
	if !isolated {
		return []string{sMuted.Width(colW + 2).Render("not restricted by this policy (" + dir + ")")}, nil
	}
	if len(rules) == 0 {
		return []string{sBoxDeny.Width(colW).Render(sFail.Render("DENY ALL") + "\n" + sMuted.Render(dir+" isolated, no allow rule"))}, nil
	}
	boxes := []string{}
	for _, r := range rules {
		lines := []string{}
		title := ruleTitle(r)
		if r.Deny {
			title = sFail.Render("DENY ") + title
		}
		if r.L7 {
			title += sWarn.Render(" L7")
		}
		lines = append(lines, sTitle.Render(title))
		for _, peer := range r.Peers {
			lines = append(lines, peer.Label)
			if peer.Matches != nil {
				if len(peer.Matches) == 0 {
					lines = append(lines, sMuted.Render("  ↳ matches no workload"))
				} else {
					names := []string{}
					for i, mm := range peer.Matches {
						if i == 4 {
							names = append(names, fmt.Sprintf("+%d", len(peer.Matches)-4))
							break
						}
						names = append(names, refKey(mm))
					}
					lines = append(lines, sMuted.Render("  ↳ "+strings.Join(names, ", ")))
				}
			}
		}
		style := sBox
		if r.Deny {
			style = sBoxDeny
		}
		boxes = append(boxes, style.Width(colW).Render(strings.Join(lines, "\n")))
	}
	return boxes, rules
}

func ruleTitle(r policy.RuleView) string {
	external, any := true, true
	for _, p := range r.Peers {
		if p.Type != "any" {
			any = false
		}
		if p.Type == "pods" || p.Type == "namespace" {
			external = false
		}
	}
	switch {
	case any:
		return "Anywhere"
	case external:
		return "Outside cluster"
	}
	return "In cluster"
}

func renderTrace(r *policy.PathResult, w int) string {
	glyph := map[policy.LayerStatus]string{policy.LayerPass: sOK.Render("✓"), policy.LayerFail: sFail.Render("✗"), policy.LayerWarn: sWarn.Render("!"), policy.LayerSkip: sMuted.Render("–")}
	lines := []string{sTitle.Render("Path: " + r.SrcRef + "  →  " + r.DstRef)}
	for _, l := range r.Layers {
		lines = append(lines, fmt.Sprintf("  %s %-14s %s", glyph[l.Status], l.Name, l.Summary))
		for _, d := range l.Detail {
			lines = append(lines, sMuted.Render("                   "+d))
		}
	}
	vs := sOK
	switch r.Status() {
	case policy.LayerFail:
		vs = sFail
	case policy.LayerWarn:
		vs = sWarn
	}
	lines = append(lines, "", "  Verdict: "+vs.Render(r.Verdict()))
	for _, l := range r.Layers {
		if l.Fix != "" {
			lines = append(lines, "", sTitle.Render("  How to fix ("+l.Name+"):"), "  "+strings.ReplaceAll(l.Fix, "\n", "\n  "))
		}
	}
	lines = append(lines, "", sMuted.Render("esc: back"))
	return lipgloss.NewStyle().Width(w).Render(strings.Join(lines, "\n"))
}

/* ---------- overlays ---------- */

func (m Model) renderHelp() string {
	rows := [][2]string{
		{"↑ ↓ / j k", "move"}, {"pgup pgdn g G", "page, first, last"}, {"tab", "next pane"}, {"1 2 3", "policies, connections, workloads"},
		{"enter", "open · trace a connection · a workload's connections"}, {"t", "trace any source → destination (Service, workload, internet)"},
		{"y", "YAML of the selected policy"}, {"/  esc", "filter · clear"}, {"d", "show or hide denied connections"},
		{"r", "re-read the cluster"}, {"mouse", "click to select, wheel to scroll"}, {"q", "quit"},
	}
	lines := []string{sTitle.Render("netpol-map keys"), ""}
	for _, r := range rows {
		lines = append(lines, sAccent.Render(fmt.Sprintf("%-16s", r[0]))+r[1])
	}
	lines = append(lines, "", sMuted.Render("any key closes this"))
	return sModal.Render(strings.Join(lines, "\n"))
}

func (m Model) renderPicker() string {
	p := m.pick
	titles := []string{"Trace: pick the source", "Trace: pick the destination", "Trace: destination port"}
	lines := []string{sTitle.Render(titles[p.step])}
	if p.src != "" {
		lines = append(lines, sMuted.Render("source      ")+p.src)
	}
	if p.dst != "" {
		lines = append(lines, sMuted.Render("destination ")+p.dst)
	}
	lines = append(lines, p.filter.View(), "")
	if p.step < 2 {
		items, labels := p.visible()
		for i := p.offset; i < len(items) && i < p.offset+12; i++ {
			if i == p.idx {
				lines = append(lines, sSel.Render(fmt.Sprintf("%-*s", 70, trunc(items[i], 70))))
			} else {
				lines = append(lines, trunc(labels[i], 90))
			}
		}
		if len(items) == 0 {
			lines = append(lines, sMuted.Render("no match"))
		}
		lines = append(lines, "", sMuted.Render("↑↓ move · enter choose · esc cancel"))
	} else {
		lines = append(lines, sMuted.Render("enter runs the trace (port optional) · esc cancel"))
	}
	return sModal.Width(min(m.width-6, 96)).Render(strings.Join(lines, "\n"))
}

func trunc(s string, n int) string {
	if n <= 1 || len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
