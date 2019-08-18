package watch

import (
	"context"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
)

var defaultTTL = 4000 * time.Millisecond

func init() {
	customFormatter := new(logrus.TextFormatter)
	customFormatter.TimestampFormat = "2006-01-02 15:04:05"
	customFormatter.FullTimestamp = true
	logrus.SetFormatter(customFormatter)
}

type Watcher struct {
	events chan Event
}

func NewWatcher() *Watcher {
	return &Watcher{
		events: make(chan Event, 32),
	}
}

func (w *Watcher) Watch(ctx context.Context) error {
	diffs, err := w.Scan(ctx)
	if err != nil {
		return err
	}
	w.Respond(diffs)
	return nil
}

func (w *Watcher) Scan(ctx context.Context) (<-chan Diff, error) {
	iface := os.Getenv("IFACE")
	if iface == "" {
		log.Fatal("must provide env IFACE")
	}
	h, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever)
	if err != nil {
		return nil, err
	}
	src := gopacket.NewPacketSource(h, h.LinkType())
	diffs := make(chan Diff, 32)
	hosts := make(map[MAC]Host)
	go func() {
		defer close(diffs)
		DiffPackets(w.events, diffs, hosts, src.Packets())
	}()
	return diffs, nil
}

func (w *Watcher) Respond(diffs <-chan Diff) error {
	go func() {
		defer close(w.events)
		for diff := range diffs {
			if diff.New {
				w.events <- Event{
					Kind: HostNew,
					Body: EventHostNew{diff.B},
				}
				continue
			} else if diff.B.LastSeen.Sub(diff.A.LastSeen) > defaultTTL {
				w.events <- Event{
					Kind: HostReturn,
					Body: EventHostReturn{diff},
				}
			}
		}
	}()
	for event := range w.events {
		switch event.Kind {
		case HostNew:
			e := event.Body.(EventHostNew)
			log.Infof("new host %s", e.Host)
		case HostDrop:
			e := event.Body.(EventHostDrop)
			log.Infof(
				"drop host (up %v) %s",
				time.Since(e.Host.FirstSeen),
				e,
			)
		case HostReturn:
			e := event.Body.(EventHostReturn)
			log.Infof(
				"return host (down %v) (since %v) %s",
				time.Since(e.Diff.A.LastSeen),
				e.Diff.B.FirstSeen.Format("2006-01-02"),
				e.Diff.B,
			)
		}
	}
	return nil
}
