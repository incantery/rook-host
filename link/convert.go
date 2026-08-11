package link

import (
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	linkv1 "github.com/incantery/rook-host/gen/rook/link/v1"
	"github.com/incantery/rook-host/projection"
)

// Converters between the in-memory canon (projection, with the clamps)
// and the wire shape (linkv1, which every client generates). The Go
// types stay authoritative; these functions are the only place the two
// vocabularies meet.

func statusToProto(s projection.Status, at time.Time) *linkv1.Status {
	out := &linkv1.Status{
		Hostname:    s.Hostname,
		RookVersion: s.RookVersion,
		HostId:      s.HostID,
		Usage:       usageToProto(s.Usage),
	}
	if !at.IsZero() {
		out.At = timestamppb.New(at)
	}
	for _, w := range s.Workspaces {
		pw := &linkv1.Workspace{
			Name:      w.Name,
			Branch:    w.Branch,
			Attention: int32(w.Attention),
		}
		for _, a := range w.Agents {
			pa := &linkv1.Agent{
				Id:      a.ID,
				State:   stateToProto(a.State),
				Title:   a.Title,
				Ask:     a.Ask,
				AskId:   a.AskID,
				Model:   a.Model,
				CostUsd: a.CostUSD,
				CtxPct:  int32(a.CtxPct),
			}
			if a.Digest != nil {
				pa.Digest = &linkv1.AgentDigest{
					Headline: a.Digest.Headline,
					Bullets:  append([]string(nil), a.Digest.Bullets...),
				}
				if !a.Digest.At.IsZero() {
					pa.Digest.At = timestamppb.New(a.Digest.At)
				}
			}
			pa.Attached = a.Attached
			pa.Now = a.Now
			if !a.NowAt.IsZero() {
				pa.NowAt = timestamppb.New(a.NowAt)
			}
			if !a.LastEvent.IsZero() {
				pa.LastEvent = timestamppb.New(a.LastEvent)
			}
			pw.Agents = append(pw.Agents, pa)
		}
		out.Workspaces = append(out.Workspaces, pw)
	}
	return out
}

func usageToProto(u *projection.Usage) *linkv1.Usage {
	if u == nil {
		return nil
	}
	out := &linkv1.Usage{
		Mode:            u.Mode,
		SessionPct:      int32(u.SessionPct),
		SessionResets:   u.SessionResets,
		WeekAllPct:      int32(u.WeekAllPct),
		WeekAllResets:   u.WeekAllResets,
		WeekModelName:   u.WeekModelName,
		WeekModelPct:    int32(u.WeekModelPct),
		WeekModelResets: u.WeekModelResets,
		AgentTodayUsd:   u.AgentTodayUSD,
		AgentWeekUsd:    u.AgentWeekUSD,
	}
	if !u.At.IsZero() {
		out.At = timestamppb.New(u.At)
	}
	return out
}

func usageFromProto(p *linkv1.Usage) *projection.Usage {
	if p == nil {
		return nil
	}
	out := &projection.Usage{
		Mode:            p.Mode,
		SessionPct:      int(p.SessionPct),
		SessionResets:   p.SessionResets,
		WeekAllPct:      int(p.WeekAllPct),
		WeekAllResets:   p.WeekAllResets,
		WeekModelName:   p.WeekModelName,
		WeekModelPct:    int(p.WeekModelPct),
		WeekModelResets: p.WeekModelResets,
		AgentTodayUSD:   p.AgentTodayUsd,
		AgentWeekUSD:    p.AgentWeekUsd,
	}
	if p.At != nil {
		out.At = p.At.AsTime()
	}
	return out
}

func statusFromProto(p *linkv1.Status) projection.Status {
	if p == nil {
		return projection.Status{}
	}
	s := projection.Status{
		Hostname:    p.Hostname,
		RookVersion: p.RookVersion,
		HostID:      p.HostId,
		Usage:       usageFromProto(p.Usage),
	}
	for _, pw := range p.Workspaces {
		w := projection.Workspace{
			Name:      pw.Name,
			Branch:    pw.Branch,
			Attention: int(pw.Attention),
		}
		for _, pa := range pw.Agents {
			a := projection.Agent{
				ID:      pa.Id,
				State:   stateFromProto(pa.State),
				Title:   pa.Title,
				Ask:     pa.Ask,
				AskID:   pa.AskId,
				Model:   pa.Model,
				CostUSD: pa.CostUsd,
				CtxPct:  int(pa.CtxPct),
			}
			if pa.Digest != nil {
				a.Digest = &projection.AgentDigest{
					Headline: pa.Digest.Headline,
					Bullets:  append([]string(nil), pa.Digest.Bullets...),
				}
				if pa.Digest.At != nil {
					a.Digest.At = pa.Digest.At.AsTime()
				}
			}
			a.Attached = pa.Attached
			a.Now = pa.Now
			if pa.NowAt != nil {
				a.NowAt = pa.NowAt.AsTime()
			}
			if pa.LastEvent != nil {
				a.LastEvent = pa.LastEvent.AsTime()
			}
			w.Agents = append(w.Agents, a)
		}
		s.Workspaces = append(s.Workspaces, w)
	}
	return s
}

func paneToProto(f projection.PaneFrame) *linkv1.PaneFrame {
	out := &linkv1.PaneFrame{
		Cols:          uint32(f.Cols),
		Rows:          uint32(f.Rows),
		CursorX:       uint32(f.CursorX),
		CursorY:       uint32(f.CursorY),
		CursorVisible: f.CursorVisible,
	}
	for _, r := range f.Lines {
		pr := &linkv1.PaneRow{Text: r.Text}
		for _, run := range r.Runs {
			pr.Runs = append(pr.Runs, &linkv1.StyleRun{
				Start: run.Start,
				Len:   run.Len,
				Fg:    run.FG,
				Bg:    run.BG,
				Attrs: run.Attrs,
			})
		}
		out.Lines = append(out.Lines, pr)
	}
	return out
}

func paneFromProto(p *linkv1.PaneFrame) projection.PaneFrame {
	if p == nil {
		return projection.PaneFrame{}
	}
	f := projection.PaneFrame{
		Cols:          int(p.Cols),
		Rows:          int(p.Rows),
		CursorX:       int(p.CursorX),
		CursorY:       int(p.CursorY),
		CursorVisible: p.CursorVisible,
	}
	for _, pr := range p.Lines {
		r := projection.PaneRow{Text: pr.Text}
		for _, run := range pr.Runs {
			r.Runs = append(r.Runs, projection.StyleRun{
				Start: run.Start,
				Len:   run.Len,
				FG:    run.Fg,
				BG:    run.Bg,
				Attrs: run.Attrs,
			})
		}
		f.Lines = append(f.Lines, r)
	}
	return f
}

// The state strings are the projection's canon ("working" |
// "needs_input" | "quiet"); anything else — an old host, a new state
// this build has not learned — crosses the wire as UNSPECIFIED rather
// than being invented.
func stateToProto(s string) linkv1.AgentState {
	switch s {
	case "working":
		return linkv1.AgentState_AGENT_STATE_WORKING
	case "needs_input":
		return linkv1.AgentState_AGENT_STATE_NEEDS_INPUT
	case "quiet":
		return linkv1.AgentState_AGENT_STATE_QUIET
	default:
		return linkv1.AgentState_AGENT_STATE_UNSPECIFIED
	}
}

func stateFromProto(s linkv1.AgentState) string {
	switch s {
	case linkv1.AgentState_AGENT_STATE_WORKING:
		return "working"
	case linkv1.AgentState_AGENT_STATE_NEEDS_INPUT:
		return "needs_input"
	case linkv1.AgentState_AGENT_STATE_QUIET:
		return "quiet"
	default:
		return ""
	}
}

func kindFromProto(k linkv1.CommandKind) string {
	switch k {
	case linkv1.CommandKind_COMMAND_KIND_COMPACT:
		return "compact"
	case linkv1.CommandKind_COMMAND_KIND_RESUME:
		return "resume"
	case linkv1.CommandKind_COMMAND_KIND_SPAWN:
		return "spawn"
	case linkv1.CommandKind_COMMAND_KIND_SAY:
		return "say"
	default:
		return ""
	}
}

func dispositionToProto(d Disposition) linkv1.Disposition {
	switch d {
	case Delivered:
		return linkv1.Disposition_DISPOSITION_DELIVERED
	case Duplicate:
		return linkv1.Disposition_DISPOSITION_DUPLICATE
	case Dropped:
		return linkv1.Disposition_DISPOSITION_DROPPED
	default:
		return linkv1.Disposition_DISPOSITION_UNSPECIFIED
	}
}

func digestToProto(d projection.Digest) *linkv1.Digest {
	out := &linkv1.Digest{
		Id:         d.ID,
		SessionId:  d.SessionID,
		Headline:   d.Headline,
		Bullets:    d.Bullets,
		FullText:   d.FullText,
		Prompt:     d.Prompt,
		Reply:      d.Reply,
		ReplyState: d.ReplyState,
		Model:      d.Model,
		CostUsd:    d.CostUSD,
	}
	if !d.At.IsZero() {
		out.At = timestamppb.New(d.At)
	}
	return out
}

func digestFromProto(p *linkv1.Digest) projection.Digest {
	if p == nil {
		return projection.Digest{}
	}
	out := projection.Digest{
		ID:         p.Id,
		SessionID:  p.SessionId,
		Headline:   p.Headline,
		Bullets:    p.Bullets,
		FullText:   p.FullText,
		Prompt:     p.Prompt,
		Reply:      p.Reply,
		ReplyState: p.ReplyState,
		Model:      p.Model,
		CostUSD:    p.CostUsd,
	}
	if p.At != nil {
		out.At = p.At.AsTime()
	}
	return out
}
