package zone

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/ferama/pigdns/pkg/utils"
	"github.com/miekg/dns"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
)

const confPollInterval = 5 * time.Second

var (
	instance *zoneFile
	once     sync.Once
)

type zoneFile struct {
	// the path of the zone file
	filePath string

	// zone origin
	origin string

	cachedZoneFileModTime time.Time

	// zone loaded records
	records []dns.RR
	// nameserver records
	ns []*dns.NS

	mu   sync.Mutex
	zfmu sync.Mutex
}

func ZoneFileInst() *zoneFile {
	once.Do(func() {
		path := viper.GetString(utils.ZoneFileFlag)
		domain := viper.GetString(utils.DomainFlag)

		instance = &zoneFile{
			filePath: path,
			origin:   fmt.Sprintf("%s.", domain),
			ns:       make([]*dns.NS, 0),
			records:  make([]dns.RR, 0),
		}

		instance.checkConfigFile()
		go instance.watchConfig()
	})

	return instance
}

// setZoneFile is actually used for tests.
// zone file path should never change during normal runs
func (z *zoneFile) setZoneFile(path string) {
	z.zfmu.Lock()
	defer z.zfmu.Unlock()

	z.filePath = path
	z.checkConfigFile()
}

// checks if config file changed and if yes reload it
func (z *zoneFile) checkConfigFile() {
	if z.filePath == "" {
		return
	}
	stat, err := os.Stat(z.filePath)
	if err != nil {
		log.Printf("[zone] failed checking key file modification time: %s", err)
	} else {
		if stat.ModTime().After(z.cachedZoneFileModTime) {
			z.loadZonefile()
			z.cachedZoneFileModTime = stat.ModTime()
		}
	}
}

// periodically run check for changes on config file
func (z *zoneFile) watchConfig() {
	for {
		z.zfmu.Lock()
		z.checkConfigFile()
		z.zfmu.Unlock()

		time.Sleep(confPollInterval)
	}
}

func (z *zoneFile) GetRecords() []dns.RR {
	z.mu.Lock()
	defer z.mu.Unlock()

	return z.records
}

func (z *zoneFile) GetNS() []*dns.NS {
	z.mu.Lock()
	defer z.mu.Unlock()

	return z.ns
}

func (z *zoneFile) loadZonefile() {
	z.mu.Lock()
	defer z.mu.Unlock()

	z.records = make([]dns.RR, 0)

	f, err := os.Open(z.filePath)
	if err != nil {
		log.Fatal().Msgf("cannot read file: %s", err)
	}
	defer f.Close()
	log.Printf("[zone] reading file '%s'", z.filePath)

	zp := dns.NewZoneParser(f, z.origin, "")
	for {
		rr, ok := zp.Next()
		if !ok {
			for _, r := range z.records {
				log.Printf("[zone] %s", r)
			}
			break
		}
		switch rr.Header().Rrtype {
		case dns.TypeNS:
			z.ns = append(z.ns, rr.(*dns.NS))
		}
		z.records = append(z.records, rr)
	}
}
