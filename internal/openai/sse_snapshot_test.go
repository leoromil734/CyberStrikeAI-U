package openai

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestSSESnapshotStreamCadenceAndIsolation(t *testing.T) {
	var stream SSESnapshotStream
	now := time.Unix(100, 0)
	metadata := map[string]interface{}{"streamId": "a"}
	first := stream.deltaAt(metadata, "a", now)
	if first["streamSeq"] != uint64(1) || first[SSEAccumulatedKey] != "a" {
		t.Fatalf("first frame: %#v", first)
	}
	second := stream.deltaAt(metadata, "aa", now.Add(time.Millisecond))
	if _, ok := second[SSEAccumulatedKey]; ok {
		t.Fatal("second frame unexpectedly repeats the full text")
	}
	if _, ok := metadata["streamSeq"]; ok {
		t.Fatal("caller metadata mutated")
	}
	if first[SSEAccumulatedKey] != "a" || first["streamSeq"] != uint64(1) {
		t.Fatal("previous frame mutated")
	}
	periodic := stream.deltaAt(metadata, "aaa", now.Add(sseSnapshotInterval))
	if periodic[SSEAccumulatedKey] != "aaa" {
		t.Fatal("time-based recovery snapshot missing")
	}
	final := stream.Final("aaaa")
	if final["streamSeq"] != uint64(4) || final[SSEAccumulatedKey] != "aaaa" || final["streamFinal"] != true || final["streamId"] != "a" {
		t.Fatalf("final frame: %#v", final)
	}
	var another SSESnapshotStream
	if another.Final("unused") != nil {
		t.Fatal("unstarted stream produced a final frame")
	}
	if another.deltaAt(map[string]interface{}{"streamId": "b"}, "b", now)["streamSeq"] != uint64(1) {
		t.Fatal("stream sequences leaked across streams")
	}
}

func TestSSESnapshotStreamImmediatelyRepairsRewrittenPrefix(t *testing.T) {
	var stream SSESnapshotStream
	now := time.Unix(100, 0)
	stream.deltaAt(map[string]interface{}{"streamId": "reason"}, "old prefix", now)
	rewritten := stream.deltaAt(map[string]interface{}{"streamId": "reason"}, "new prefix", now)
	if rewritten[SSEAccumulatedKey] != "new prefix" {
		t.Fatal("rewritten prefix was sent as an append-only delta")
	}
	shortened := stream.deltaAt(map[string]interface{}{"streamId": "reason"}, "new", now)
	if shortened[SSEAccumulatedKey] != "new" {
		t.Fatal("shortened display text did not produce a correction snapshot")
	}
}

func TestSSESnapshotStreamWireReductionAndChunkRecovery(t *testing.T) {
	var stream SSESnapshotStream
	now := time.Unix(100, 0)
	legacyBytes, sparseBytes, snapshots := 0, 0, 0
	for i := 1; i <= 1024; i++ {
		text := strings.Repeat("x", i*16)
		old, _ := json.Marshal(WithSSEAccumulated(map[string]interface{}{"streamId": "a"}, text))
		frame := stream.deltaAt(map[string]interface{}{"streamId": "a"}, text, now)
		if _, ok := frame[SSEAccumulatedKey]; ok {
			snapshots++
		}
		encoded, _ := json.Marshal(frame)
		legacyBytes += len(old) + 16
		sparseBytes += len(encoded) + 16
	}
	final, _ := json.Marshal(stream.Final(strings.Repeat("x", 1024*16)))
	sparseBytes += len(final)
	if snapshots != 8 {
		t.Fatalf("snapshot count = %d, want 8", snapshots)
	}
	if sparseBytes*10 >= legacyBytes {
		t.Fatalf("expected >90%% reduction, old=%d sparse=%d", legacyBytes, sparseBytes)
	}
	t.Logf("synthetic stream bytes: old=%d sparse=%d saved=%.2f%%", legacyBytes, sparseBytes, 100*(1-float64(sparseBytes)/float64(legacyBytes)))
}
