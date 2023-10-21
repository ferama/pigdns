package recursor

import (
	"bytes"
	"encoding/gob"
	"errors"
	"time"

	"github.com/ferama/pigdns/pkg/cache"
)

type nsCache struct {
	cache *cache.FileCache
	name  string
}

func newNSCache(datadir string, name string, size int64) *nsCache {
	c := &nsCache{
		cache: cache.NewFileCache(datadir, name, size),
		name:  name,
	}

	return c
}

func (c *nsCache) Set(as *authServers) error {
	if as == nil || len(as.List) == 0 {
		return errors.New("no servers to set")
	}
	key := as.Zone
	ttl := as.List[0].TTL

	var packed bytes.Buffer
	enc := gob.NewEncoder(&packed)
	err := enc.Encode(*as)
	if err != nil {
		return err
	}

	i := &cache.Item{
		Data: packed.Bytes(),
	}
	i.SetTTL(time.Duration(ttl) * time.Second)
	// log.Printf("[%s set] zone=%s, TTL: %d", c.name, key, ttl)
	return c.cache.Set(key, i)
}

func (c *nsCache) Get(zone string) (*authServers, error) {
	item, err := c.cache.Get(zone)
	if err != nil {
		return nil, err
	}
	// var packed bytes.Buffer
	var as authServers
	reader := bytes.NewReader(item.Data)
	dec := gob.NewDecoder(reader)
	err = dec.Decode(&as)
	if err != nil {
		return nil, err
	}
	// log.Printf("[%s get] zone=%s", c.name, as.Zone)

	return &as, nil
}
