package forward

import (
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const expiredCheckInterval = 60 * time.Second

type item struct {
	// when the item expires
	expires time.Time
	// when the item born (for eviction)
	birth time.Time

	msg []byte
}

type cache struct {
	data map[string]item

	mu sync.Mutex
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

		c.mu.Lock()
		for k, v := range c.data {
			if time.Now().After(v.expires) {
				log.Println("expired", k)
				delete(c.data, k)
			}
		}
		c.mu.Unlock()

		time.Sleep(expiredCheckInterval)
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
		birth:   time.Now(),
		msg:     packed,
	}
	return nil
}

func (c *cache) get(q dns.Question) (*dns.Msg, error) {
	key := c.buildKey(q)
	if val, ok := c.data[key]; ok {
		msg := new(dns.Msg)
		err := msg.Unpack(val.msg)
		if err != nil {
			return nil, err
		}
		return msg, nil
	}
	return nil, errors.New("item not found")
}
