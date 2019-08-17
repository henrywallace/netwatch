package watch

import (
	"context"
	"fmt"
	"time"

	"github.com/bettercap/bettercap/modules"
	"github.com/bettercap/bettercap/modules/net_recon"
	"github.com/bettercap/bettercap/network"
	"github.com/bettercap/bettercap/session"
	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
)

func init() {
	customFormatter := new(logrus.TextFormatter)
	customFormatter.TimestampFormat = "2006-01-02 15:04:05"
	customFormatter.FullTimestamp = true
	logrus.SetFormatter(customFormatter)
}

type Watcher struct {
	sess    *session.Session
	curr    map[string]TrackedEndpoint
	tracked map[string]TrackedEndpoint
	events  chan Event
}

func NewWatcher(sess *session.Session) *Watcher {
	MustRun(sess, "net.probe on")
	return &Watcher{
		sess:    sess,
		curr:    make(map[string]TrackedEndpoint),
		tracked: make(map[string]TrackedEndpoint),
		events:  make(chan Event, 32),
	}
}

func (w *Watcher) Watch(ctx context.Context) error {
	go func() {
		if err := w.Respond(); err != nil {
			log.Errorf("failed to respond: %v", err)
		}
	}()
	return w.Scan(ctx)
}

func (w *Watcher) Scan(ctx context.Context) error {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			w.Update(w.sess)
		}
	}
}

type TrackedEndpoint struct {
	Endpoint network.Endpoint
	// Since bettercap resets firstseen on return of an endpoint (it has no
	// state).
	FirstSeen time.Time
}

func (t TrackedEndpoint) String() string {
	return fmt.Sprintf(
		"%s/%s/%s",
		t.Endpoint.HW,
		t.Endpoint.IpAddress,
		t.Endpoint.Hostname,
	)
}

func (w *Watcher) Update(sess *session.Session) map[string]TrackedEndpoint {
	next := make(map[string]TrackedEndpoint)
	sess.Lan.EachHost(func(mac string, e *network.Endpoint) {
		next[mac] = TrackedEndpoint{
			Endpoint:  *e,
			FirstSeen: time.Now(),
		}
	})
	staged := make(map[string]TrackedEndpoint)
	touched := make(map[string]TrackedEndpoint)
	for mac, newEnd := range next {
		now := time.Now()
		if prev, ok := w.tracked[mac]; ok {
			if time.Since(prev.Endpoint.LastSeen) > 2*time.Second {
				w.events <- Event{
					Kind: HostReturn,
					Body: EventHostReturn{newEnd},
				}
			}
			// We subsume the first seen timestamp, since we're
			// matching an already tracked endpoint.
			newEnd.FirstSeen = prev.FirstSeen
			newEnd.Endpoint.LastSeen = now
			touched[mac] = prev
			staged[mac] = newEnd
			w.tracked[mac] = newEnd
		} else {
			newEnd.Endpoint.FirstSeen = now
			newEnd.Endpoint.LastSeen = now
			w.tracked[mac] = newEnd
			staged[mac] = newEnd
			w.events <- Event{
				Kind: HostNew,
				Body: EventHostNew{newEnd},
			}
		}
	}
	gone := make(map[string]TrackedEndpoint)
	for mac, end := range w.curr {
		if _, ok := touched[mac]; !ok {
			gone[mac] = end
		}
	}
	for _, e := range gone {
		w.events <- Event{
			Kind: HostDrop,
			Body: EventHostDrop{e},
		}
	}
	w.curr = staged
	return nil
}

func (w *Watcher) Respond() error {
	for event := range w.events {
		switch event.Kind {
		case HostNew:
			e := event.Body.(EventHostNew)
			log.Infof("new host %s", e)
		case HostDrop:
			e := event.Body.(EventHostDrop)
			log.Infof(
				"drop host (up %v) %s",
				time.Since(e.Endpoint.FirstSeen),
				e,
			)
		case HostReturn:
			e := event.Body.(EventHostReturn)
			log.Infof(
				"return host (down %v) (since %v) %s",
				time.Since(e.Endpoint.LastSeen),
				e.FirstSeen.Format("2006-01-02"),
				e,
			)
		}
	}
	return nil
}

func netRecon(sess *session.Session) *net_recon.Discovery {
	for _, mod := range sess.Modules {
		if mod.Name() == "net.recon" {
			return mod.(*net_recon.Discovery)
		}
	}
	log.Fatal("failed to find module net.recon")
	return nil
}

func MustRun(sess *session.Session, line string) {
	if err := sess.Run(line); err != nil {
		log.Fatalf("failed to run '%s': %v", line, err)
	}
}

// StartSession starts a new bettercap session with all the modules loaded.
func StartSession() (*session.Session, error) {
	sess, err := session.New()
	if err != nil {
		return nil, err
	}
	modules.LoadModules(sess)
	if err := sess.Start(); err != nil {
		return nil, err
	}
	return sess, err
}
