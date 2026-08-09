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
			if !a.LastEvent.IsZero() {
				pa.LastEvent = timestamppb.New(a.LastEvent)
			}
			pw.Agents = append(pw.Agents, pa)
		}
		out.Workspaces = append(out.Workspaces, pw)
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
			if pa.LastEvent != nil {
				a.LastEvent = pa.LastEvent.AsTime()
			}
			w.Agents = append(w.Agents, a)
		}
		s.Workspaces = append(s.Workspaces, w)
	}
	return s
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
