package recursor

import (
	"bytes"
	"encoding/gob"
	"errors"
	"time"

	"github.com/ferama/pigdns/pkg/cache"
	"github.com/ferama/pigdns/pkg/metrics"
)

type nsCacheItem struct {
	Zone string
	List []*nsServer
}

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
	if as == nil {
		return errors.New("no servers to set")
	}
	as.RLock()
	defer as.RUnlock()

	if len(as.List) == 0 {
		return errors.New("no servers to set")
	}

	key := as.Zone
	ttl := as.List[0].TTL

	var packed bytes.Buffer
	enc := gob.NewEncoder(&packed)

	// this extra conversion step is needed
	// becaouse the glob ancoder cannot encode the
	// mutex
	item := nsCacheItem{
		Zone: as.Zone,
		List: as.List,
	}

	err := enc.Encode(item)
	if err != nil {
		return err
	}

	i := &cache.Item{
		Data: packed.Bytes(),
	}
	i.SetTTL(time.Duration(ttl) * time.Second)

	metrics.Instance().QueryCacheMiss()
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
	var nsItem nsCacheItem
	reader := bytes.NewReader(item.Data)
	dec := gob.NewDecoder(reader)
	err = dec.Decode(&nsItem)
	if err != nil {
		return nil, err
	}
	as.List = nsItem.List
	as.Zone = nsItem.Zone
	// log.Printf("[%s get] zone=%s", c.name, as.Zone)

	metrics.Instance().QueryCacheHit()
	return &as, nil
}
