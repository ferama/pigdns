package recursor

import (
	"bytes"
	"encoding/gob"
	"errors"
	"time"

	"github.com/ferama/pigdns/pkg/cache"
	"github.com/ferama/pigdns/pkg/metrics"
	"github.com/miekg/dns"
)

// a custom dns.RR implementation to be able to use gob
type gobRR struct {
	Rr string
}

type keyCacheItem struct {
	Zone string
	Keys []gobRR
}

type keyCache struct {
	cache cache.Cache
	name  string
}

func newKeyCache(datadir string, name string, size int, cachePersistence bool) *keyCache {
	c := &keyCache{
		cache: cache.NewFileCache(datadir, name, size, cachePersistence),
		name:  name,
	}

	return c
}

func (c *keyCache) Set(zone string, keys []dns.RR) error {
	if len(keys) == 0 {
		return errors.New("no keys to set")
	}

	ttl := keys[0].Header().Ttl

	var packed bytes.Buffer
	enc := gob.NewEncoder(&packed)

	gobs := make([]gobRR, len(keys))
	for i, rr := range keys {
		gobs[i] = gobRR{Rr: rr.String()}
	}

	item := keyCacheItem{
		Zone: zone,
		Keys: gobs,
	}

	err := enc.Encode(item)
	if err != nil {
		return err
	}

	i := &cache.Item{
		Data: packed.Bytes(),
	}
	i.SetTTL(time.Duration(ttl) * time.Second)

	metrics.Instance().ExchangeCacheMiss()
	return c.cache.Set(zone, i)
}

func (c *keyCache) Get(zone string) ([]dns.RR, error) {
	item, err := c.cache.Get(zone)
	if err != nil {
		return nil, err
	}
	var kci keyCacheItem
	reader := bytes.NewReader(item.Data)
	dec := gob.NewDecoder(reader)
	err = dec.Decode(&kci)
	if err != nil {
		return nil, err
	}

	keys := make([]dns.RR, len(kci.Keys))
	for i, gob := range kci.Keys {
		rr, err := dns.NewRR(gob.Rr)
		if err != nil {
			return nil, err
		}
		keys[i] = rr
	}

	metrics.Instance().ExchangeCacheHit()
	return keys, nil
}
