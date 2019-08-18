package watch

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/sirupsen/logrus"
)

var (
	ttlHost = 60 * time.Second
)

type Watcher struct {
	log    *logrus.Logger
	events chan Event
}

func NewWatcher(log *logrus.Logger) *Watcher {
	return &Watcher{
		log:    log,
		events: make(chan Event, 32),
	}
}

func (w *Watcher) Watch(ctx context.Context) error {
	iface := os.Getenv("IFACE")
	if iface == "" {
		w.log.Fatal("must provide env IFACE")
	}
	h, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever)
	if err != nil {
		return err
	}
	src := gopacket.NewPacketSource(h, h.LinkType())
	hosts := make(map[MAC]*Host)
	go w.ScanPackets(hosts, src.Packets())
	return w.Respond()
}

func (w *Watcher) Respond() error {
	for e := range w.events {
		switch e.Kind {
		case HostNew:
			e := e.Body.(EventHostNew)
			w.log.Infof("new %s", e.Host)
		case HostDrop:
			e := e.Body.(EventHostDrop)
			w.log.Infof("drop (up %s): %s", e.Up, e.Host)
		case HostReturn:
			e := e.Body.(EventHostReturn)
			w.log.Infof("return (down %s): %s", e.Down, e.Host)
		default:
			panic(fmt.Sprintf("unhandled event kind: %#v", e))
		}
	}
	return nil
}
