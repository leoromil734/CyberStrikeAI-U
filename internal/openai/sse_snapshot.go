package openai

import (
	"strings"
	"time"
)

const (
	// Bound recovery time while avoiding a full-text copy on every token.
	sseSnapshotInterval = 2 * time.Second
	sseSnapshotChunks   = 128
)

// SSESnapshotStream encodes one ordered stream. It belongs to a single producer
// and must not be shared between stream IDs or concurrent callbacks. The zero
// value is ready to use. Consumers append message verbatim for contiguous
// streamSeq values; after a gap they wait for the next accumulated snapshot.
// The final snapshot also repairs a subscriber which joined mid-stream.
type SSESnapshotStream struct {
	sequence     uint64
	lastSnapshot time.Time
	snapshotSeq  uint64
	metadata     map[string]interface{}
	previousText string
}

// Delta sends the first and periodic authoritative snapshots, not one per token.
// Neither the caller's metadata nor previously returned frames are mutated.
func (s *SSESnapshotStream) Delta(data map[string]interface{}, accumulated string) map[string]interface{} {
	return s.deltaAt(data, accumulated, time.Now())
}

func (s *SSESnapshotStream) deltaAt(data map[string]interface{}, accumulated string, now time.Time) map[string]interface{} {
	s.sequence++
	s.metadata = cloneSSEMetadata(data)
	out := cloneSSEMetadata(s.metadata)
	out["streamSeq"] = s.sequence
	// Reasoning display normalization can rewrite a previously emitted prefix.
	// Such updates must be authoritative immediately, never appended as deltas.
	rewritten := !strings.HasPrefix(accumulated, s.previousText)
	s.previousText = accumulated
	if s.sequence == 1 || rewritten || s.sequence-s.snapshotSeq >= sseSnapshotChunks || now.Sub(s.lastSnapshot) >= sseSnapshotInterval {
		out[SSEAccumulatedKey] = accumulated
		s.lastSnapshot = now
		s.snapshotSeq = s.sequence
	}
	return out
}

// Final produces a final empty-message delta with a full snapshot. It returns
// nil if this stream never emitted content (for example a suppressed duplicate).
func (s *SSESnapshotStream) Final(accumulated string) map[string]interface{} {
	if s.sequence == 0 {
		return nil
	}
	s.sequence++
	out := cloneSSEMetadata(s.metadata)
	out["streamSeq"] = s.sequence
	out["streamFinal"] = true
	out[SSEAccumulatedKey] = accumulated
	return out
}

func cloneSSEMetadata(data map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(data)+2)
	for key, value := range data {
		if key != SSEAccumulatedKey && key != "streamSeq" && key != "streamFinal" {
			out[key] = value
		}
	}
	return out
}
