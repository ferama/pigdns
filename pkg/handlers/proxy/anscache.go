package proxy

import (
	"errors"
	"time"

	"github.com/ferama/pigdns/pkg/cache"
	"github.com/ferama/pigdns/pkg/metrics"
	"github.com/ferama/pigdns/pkg/utils"
	"github.com/miekg/dns"
)

var (
	errMsgIsNull = errors.New("msg is null")
)

type ansCache struct {
	cache cache.Cache
	name  string
}

// this is a cache for answers in the dns.Msg form
func newAnsCache(datadir string, name string, size int) *ansCache {
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

	// do not cache failures for long time
	if m.Rcode != dns.RcodeSuccess {
		minTTL = utils.MsgMinTTL
	}

	utils.MsgRemoveOPT(m)

	packed, err := m.Pack()
	if err != nil {
		return err
	}

	i := &cache.Item{
		Data: packed,
	}
	i.SetTTL(time.Duration(minTTL) * time.Second)
	// log.Printf("[%s set] %s, ttl:%fs, minTTL: %d", c.name, key, time.Until(i.Expires).Seconds(), minTTL)

	metrics.Instance().ExchangeCacheMiss()
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

	do := utils.MsgGetDo(msg)

	ts := time.Until(item.Expires).Seconds()
	// if item is still not deleted from cache (the go routine
	// runs once each cacheExpiredCheckInterval seconds)
	// ts could be negative.
	if ts < 0 {
		ts = 0
	}
	ttl := uint32(ts)
	minTTL := utils.MsgGetMinTTL(msg)

	setTTL := func(rr dns.RR, minTTL, ttl uint32) {
		var diff uint32
		diff = 0
		if minTTL > ttl {
			diff = minTTL - ttl
		}
		if rr.Header().Ttl > diff {
			rr.Header().Ttl -= diff
		} else {
			rr.Header().Ttl = 0
		}
	}

	for _, a := range msg.Answer {
		setTTL(a, minTTL, ttl)
	}
	for _, a := range msg.Extra {
		setTTL(a, minTTL, ttl)
	}
	for _, a := range msg.Ns {
		setTTL(a, minTTL, ttl)
	}

	if do {
		utils.MsgSetAuthenticated(msg, true)
	}

	metrics.Instance().ExchangeCacheHit()
	// log.Printf("[%s get] key=%s", c.name, key)
	return msg, nil
}
