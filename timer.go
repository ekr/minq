package minq

import (
	"time"
)

type timerCb func()

type timer struct {
	ts       *timerSet
	cb       timerCb
	deadline time.Time
}

// This is a simple implementation of unsorted timers.
// TODO(ekr@rtfm.com): Need a better data structure.
type timerSet struct {
	ts []*timer
}

func newTimers() *timerSet {
	return &timerSet{nil}
}

func (ts *timerSet) start(cb timerCb, delayMs uint32) *timer {
	t := timer{
		ts,
		cb,
		time.Now().Add(time.Millisecond * time.Duration(delayMs)),
	}

	ts.ts = append(ts.ts, &t)

	return &t
}

func (ts *timerSet) check(now time.Time) {
	for i, t := range ts.ts {
		if now.After(t.deadline) {
			ts.ts = append(ts.ts[:i], ts.ts[:i+1]...)
			if t.cb != nil {
				t.cb()
			}
		}
	}
}

func (t *timer) cancel() {
	t.cb = nil
}
