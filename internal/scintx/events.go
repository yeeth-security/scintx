package scintx

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync/atomic"
	"time"
)

type EventEmitter struct {
	Source string
	Store  *Store
	seq    uint64
}

func NewEventEmitter(source string, store *Store) *EventEmitter {
	return &EventEmitter{Source: source, Store: store}
}

func (e *EventEmitter) Emit(eventType, subject string, data map[string]any) {
	s := atomic.AddUint64(&e.seq, 1)
	seq := int(s)
	evt := CloudEvent{
		SpecVersion:     "1.0",
		ID:              "evt_" + randHex(),
		Source:          e.Source,
		Type:            eventType,
		Subject:         subject,
		Time:            time.Now().UTC(),
		DataContentType: "application/json",
		Data:            data,
		Sequence:        &seq,
	}
	e.Store.AppendEvent(evt)
}

func RandHex() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b) + fmt.Sprintf("-%d", time.Now().UnixNano()%100000)
}

func randHex() string {
	return RandHex()
}