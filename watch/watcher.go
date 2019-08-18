package watch

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
)

var defaultTTL = 1 * time.Minute

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
	iface := os.Getenv("IFACE")
	if iface == "" {
		log.Fatal("must provide env IFACE")
	}
	h, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever)
	if err != nil {
		return err
	}
	src := gopacket.NewPacketSource(h, h.LinkType())
	hosts := make(map[MAC]*Host)
	go ScanPackets(w.events, hosts, src.Packets())
	return w.Respond()
}

func (w *Watcher) Respond() error {
	for e := range w.events {
		switch e.Kind {
		case HostNew:
			e := e.Body.(EventHostNew)
			log.Infof("new host: %s", e.Host)
		case HostDrop:
			e := e.Body.(EventHostDrop)
			log.Infof("drop host (up %s): %s", e.Up, e.Host)
		case HostReturn:
			e := e.Body.(EventHostReturn)
			log.Infof("return host (down %s): %s", e.Down, e.Host)
		default:
			panic(fmt.Sprintf("unhandled event kind: %#v", e))
		}
	}
	return nil
}
