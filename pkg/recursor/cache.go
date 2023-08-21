package recursor

import (
	"fmt"
	"time"

	"github.com/ferama/pigdns/pkg/cache"
	"github.com/ferama/pigdns/pkg/utils"
	"github.com/miekg/dns"
	"github.com/rs/zerolog/log"
)

type recursorCache struct {
	cache *cache.FileCache
}

func newRecursorCache(datadir string) *recursorCache {
	rc := &recursorCache{
		cache: cache.NewFileCache(datadir),
	}

	return rc
}

func (c *recursorCache) buildKey(q dns.Question, nsaddr string) string {
	return fmt.Sprintf("%s_%s_%d_%d", nsaddr, q.Name, q.Qtype, q.Qclass)
}

func (c *recursorCache) Set(q dns.Question, nsaddr string, m *dns.Msg) error {
	key := c.buildKey(q, nsaddr)

	minTTL := utils.MsgGetMinTTL(m)

	packed, err := m.Pack()
	if err != nil {
		return err
	}

	i := &cache.Item{
		Data: packed,
	}
	i.SetTTL(time.Duration(minTTL) * time.Second)
	log.Printf("[cache set] %s, ttl:%fs, minTTL: %d", key, time.Until(i.Expires).Seconds(), minTTL)
	// log.Printf("[cache set] %s, ttl:%fs, minTTL: %d, ans: %s, extra: %s", key, time.Until(i.Expires).Seconds(), minTTL, m.Answer, m.Extra)
	// log.Printf("msg: %s", m)
	return c.cache.Set(key, i)
}

func (c *recursorCache) Get(q dns.Question, nsaddr string) (*dns.Msg, error) {
	key := c.buildKey(q, nsaddr)
	item, err := c.cache.Get(key)
	if err != nil {
		return nil, err
	}
	msg := new(dns.Msg)
	err = msg.Unpack(item.Data)
	if err != nil {
		return nil, err
	}

	ts := time.Until(item.Expires).Seconds()
	// if item is still not deleted from cache (the go routine
	// runs once each cacheExpiredCheckInterval seconds)
	// ts could be negative.
	if ts < 0 {
		ts = 0
	}
	ttl := uint32(ts)
	for _, a := range msg.Answer {
		a.Header().Ttl = ttl
	}
	for _, a := range msg.Extra {
		a.Header().Ttl = ttl
	}
	for _, a := range msg.Ns {
		a.Header().Ttl = ttl
	}
	return msg, nil
}
