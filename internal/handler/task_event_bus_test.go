package handler

import (
	"bytes"
	"testing"
)

func TestTaskEventSubscriberKeepsNewestSnapshot(t *testing.T) {
	s := &taskEventSub{ch: make(chan []byte, 2)}
	s.sendNonBlocking([]byte("oldest"))
	s.sendNonBlocking([]byte("old"))
	if !s.sendNonBlocking([]byte("final-snapshot")) {
		t.Fatal("newest snapshot was dropped")
	}
	if got := <-s.ch; !bytes.Equal(got, []byte("old")) {
		t.Fatalf("oldest frame not evicted: %q", got)
	}
	if got := <-s.ch; !bytes.Equal(got, []byte("final-snapshot")) {
		t.Fatalf("final snapshot missing: %q", got)
	}
	s.closeOnce()
	if s.sendNonBlocking([]byte("late")) {
		t.Fatal("published to a closed subscription")
	}
}

func TestTaskEventUnsubscribeDoesNotCloseOtherSubscribers(t *testing.T) {
	bus := NewTaskEventBus()
	old, _ := bus.Subscribe("conversation")
	newSub, ch := bus.Subscribe("conversation")
	bus.Unsubscribe("conversation", old)
	bus.Publish("conversation", []byte("new event"))
	select {
	case got := <-ch:
		if string(got) != "new event" {
			t.Fatalf("got %q", got)
		}
	default:
		t.Fatal("unsubscribing old client interrupted new subscriber")
	}
	bus.Unsubscribe("conversation", newSub)
}
