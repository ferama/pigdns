package zone

import (
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const confPollInterval = 5 * time.Second

type ZoneFile struct {
	file                  string
	origin                string
	cachedZoneFileModTime time.Time

	records []dns.RR

	mu sync.Mutex
}

func NewZoneFile(path string, domain string) *ZoneFile {
	z := &ZoneFile{
		file:   path,
		origin: fmt.Sprintf("%s.", domain),
	}
	go z.watchConfig()
	return z
}

func (z *ZoneFile) watchConfig() {
	for {
		stat, err := os.Stat(z.file)
		if err != nil {
			log.Println("failed checking key file modification time:", err)
		} else {
			if stat.ModTime().After(z.cachedZoneFileModTime) {
				z.loadZonefile()
				z.cachedZoneFileModTime = stat.ModTime()
			}
		}
		time.Sleep(confPollInterval)
	}
}

func (z *ZoneFile) GetRecords() []dns.RR {
	z.mu.Lock()
	defer z.mu.Unlock()

	return z.records
}

func (z *ZoneFile) loadZonefile() {
	z.mu.Lock()
	defer z.mu.Unlock()

	z.records = make([]dns.RR, 0)

	f, err := os.Open(z.file)
	if err != nil {
		log.Fatalf("cannot read file: %s", err)
	}
	defer f.Close()
	log.Printf("[zone] reading file '%s'", z.file)

	zp := dns.NewZoneParser(f, z.origin, "")
	for {
		rr, ok := zp.Next()
		if !ok {
			for _, r := range z.records {
				log.Println("[zone]", r)
			}
			break
		}
		z.records = append(z.records, rr)
	}
}
