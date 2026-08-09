// Package edge holds the shared constants of the edge protocol — the
// strings both ends of the wire must agree on. The cloud gateway and
// every device client import these from here, so the protocol version
// and the event-type vocabulary have exactly one definition.
package edge

// ProtocolVersion is what this generation of the edge protocol speaks.
// Devices send theirs; nothing is refused on version yet, but both
// sides are on the record.
const ProtocolVersion = "rook-edge/1"

// EventTypeCommandResult is the device event type carrying a
// CommandResult payload.
const EventTypeCommandResult = "com.rook.edge.command_result.v1"

// EventTypeAgentEvent is the device event type carrying an AgentEvent
// payload — session lifecycle, never a command resolution.
const EventTypeAgentEvent = "com.rook.edge.agent_event.v1"
