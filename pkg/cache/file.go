package cache

import (
	"bytes"
	"encoding/gob"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	cacheExpiredCheckInterval = 10 * time.Second
	cacheMaxItems             = 5000
)

type item struct {
	// when the item Expires
	Expires time.Time

	Msg []byte
}

type FileCache struct {
	data    map[string]item
	datadir string

	mu sync.RWMutex
}

func NewFileCache(datadir string) *FileCache {
	c := &FileCache{
		data:    make(map[string]item),
		datadir: datadir,
	}
	c.load()
	go c.checkExpired()
	return c
}

func (c *FileCache) dump() {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(c.data)
	if err != nil {
		log.Println("[cache] cannot dump cache", err)
		return
	}

	path := filepath.Join(c.datadir, "pig.cache")
	fi, err := os.Create(path)
	if err != nil {
		log.Println("[cache] cannot store cache", err)
		return
	}
	defer fi.Close()
	fi.Write(buf.Bytes())
}

func (c *FileCache) load() {
	path := filepath.Join(c.datadir, "pig.cache")
	b, err := os.ReadFile(path)
	if err != nil {
		log.Println("[cache] cannot read cache file", err)
		return
	}

	d := gob.NewDecoder(bytes.NewBuffer(b))
	err = d.Decode(&c.data)
	if err != nil {
		log.Println("[cache] cannot load cache", err)
	}
	log.Printf("[cache] loaded items %d/%d", len(c.data), cacheMaxItems)
}

func (c *FileCache) checkExpired() {
	for {

		s := make([]struct {
			k string
			t time.Time
		}, 0)

		c.mu.Lock()
		for k, v := range c.data {
			if time.Now().After(v.Expires) {
				log.Println("[cache] expired", k)
				delete(c.data, k)
			}
			s = append(s, struct {
				k string
				t time.Time
			}{k: k, t: v.Expires})
		}
		c.mu.Unlock()

		if len(c.data) > cacheMaxItems {
			sort.Slice(s, func(i, j int) bool {
				t1 := s[i].t
				t2 := s[j].t
				return t2.After(t1)
			})

			ei := len(s) - cacheMaxItems
			c.mu.Lock()
			for _, i := range s[:ei] {
				log.Println("[cache] evicted", i.k)
				delete(c.data, i.k)
			}
			c.mu.Unlock()
		}

		c.mu.Lock()
		c.dump()
		c.mu.Unlock()
		log.Printf("[cache] total items %d/%d", len(c.data), cacheMaxItems)

		time.Sleep(cacheExpiredCheckInterval)
	}
}

func (c *FileCache) buildKey(q dns.Question) string {
	return fmt.Sprintf("%s_%d_%d", q.Name, q.Qtype, q.Qclass)
}

func (c *FileCache) Set(q dns.Question, m *dns.Msg) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	packed, err := m.Pack()
	if err != nil {
		return err
	}

	var minTTL uint32
	minTTL = 0
	for _, a := range m.Answer {
		ttl := a.Header().Ttl
		if minTTL == 0 || ttl < minTTL {
			minTTL = ttl
		}
	}
	expireTime := time.Now().Add(time.Duration(minTTL) * time.Second)
	key := c.buildKey(q)

	c.data[key] = item{
		Expires: expireTime,
		Msg:     packed,
	}
	return nil
}

func (c *FileCache) Get(q dns.Question) (*dns.Msg, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	key := c.buildKey(q)
	if val, ok := c.data[key]; ok {
		msg := new(dns.Msg)
		err := msg.Unpack(val.Msg)
		if err != nil {
			return nil, err
		}
		for _, a := range msg.Answer {
			a.Header().Ttl = uint32(time.Until(val.Expires).Seconds())
		}
		return msg, nil
	}
	return nil, errors.New("item not found")
}
