package zone

import (
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

const confPollInterval = 5 * time.Second

var (
	instance *ZoneFile
	once     sync.Once
)

type ZoneFile struct {
	file                  string
	origin                string
	cachedZoneFileModTime time.Time

	records []dns.RR

	mu   sync.Mutex
	zfmu sync.Mutex
}

func ZoneFileInst() *ZoneFile {
	once.Do(func() {
		path := viper.GetString("zone-file")
		domain := viper.GetString("domain")

		instance = &ZoneFile{
			file:   path,
			origin: fmt.Sprintf("%s.", domain),
		}

		instance.checkConfigFile()
		go instance.watchConfig()
	})

	return instance
}

// setZoneFile is actually used for tests.
// zone file path should never change during normal runs
func (z *ZoneFile) setZoneFile(path string) {
	z.zfmu.Lock()
	defer z.zfmu.Unlock()

	z.file = path
	z.checkConfigFile()
}

// checks if config file changed and if yes reload it
func (z *ZoneFile) checkConfigFile() {
	stat, err := os.Stat(z.file)
	if err != nil {
		log.Println("failed checking key file modification time:", err)
	} else {
		if stat.ModTime().After(z.cachedZoneFileModTime) {
			z.loadZonefile()
			z.cachedZoneFileModTime = stat.ModTime()
		}
	}
}

// periodically run check for changes on config file
func (z *ZoneFile) watchConfig() {
	for {
		z.zfmu.Lock()
		z.checkConfigFile()
		z.zfmu.Unlock()

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
