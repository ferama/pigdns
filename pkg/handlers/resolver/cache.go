package resolver

import (
	"errors"
	"fmt"
	"log"
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
	// when the item expires
	expires time.Time

	msg []byte
}

type cache struct {
	data map[string]item

	mu sync.RWMutex
}

func newCache() *cache {
	c := &cache{
		data: make(map[string]item),
	}
	go c.checkExpired()
	return c
}

func (c *cache) checkExpired() {
	for {

		s := make([]struct {
			k string
			t time.Time
		}, 0)

		c.mu.Lock()
		for k, v := range c.data {
			if time.Now().After(v.expires) {
				log.Println("[cache] expired", k)
				delete(c.data, k)
			}
			s = append(s, struct {
				k string
				t time.Time
			}{k: k, t: v.expires})
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
		log.Printf("[cache] total items %d/%d", len(c.data), cacheMaxItems)

		time.Sleep(cacheExpiredCheckInterval)
	}
}

func (c *cache) buildKey(q dns.Question) string {
	return fmt.Sprintf("%s_%d_%d", q.Name, q.Qtype, q.Qclass)
}

func (c *cache) set(q dns.Question, m *dns.Msg) error {
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
		expires: expireTime,
		msg:     packed,
	}
	return nil
}

func (c *cache) get(q dns.Question) (*dns.Msg, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	key := c.buildKey(q)
	if val, ok := c.data[key]; ok {
		msg := new(dns.Msg)
		err := msg.Unpack(val.msg)
		if err != nil {
			return nil, err
		}
		for _, a := range msg.Answer {
			a.Header().Ttl = uint32(time.Until(val.expires).Seconds())
		}
		return msg, nil
	}
	return nil, errors.New("item not found")
}
