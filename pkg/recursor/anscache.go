package recursor

import (
	"errors"
	"time"

	"github.com/ferama/pigdns/pkg/cache"
	"github.com/ferama/pigdns/pkg/utils"
	"github.com/miekg/dns"
)

var (
	errMsgIsNull = errors.New("recursion max level reached")
)

type ansCache struct {
	cache *cache.FileCache
	name  string
}

// this is a cache for answers in the dns.Msg form
func newAnsCache(datadir string, name string, size int64) *ansCache {
	rc := &ansCache{
		cache: cache.NewFileCache(datadir, name, size),
		name:  name,
	}

	return rc
}

func (c *ansCache) Set(key string, m *dns.Msg) error {
	if m == nil {
		return errMsgIsNull
	}
	minTTL := utils.MsgGetMinTTL(m)

	packed, err := m.Pack()
	if err != nil {
		return err
	}

	i := &cache.Item{
		Data: packed,
	}
	i.SetTTL(time.Duration(minTTL) * time.Second)
	// log.Printf("[%s set] %s, ttl:%fs, minTTL: %d", c.name, key, time.Until(i.Expires).Seconds(), minTTL)
	return c.cache.Set(key, i)
}

func (c *ansCache) Get(key string) (*dns.Msg, error) {
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

	// log.Printf("[%s get] key=%s", c.name, key)
	return msg, nil
}