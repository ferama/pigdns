package cache

import (
	"bytes"
	"encoding/gob"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/miekg/dns"
)

const (
	cacheExpiredCheckInterval = 10 * time.Second
	cacheMaxItemsPerBucket    = 10000
)

type item struct {
	// when the item Expires
	Expires time.Time

	Msg []byte
}

type bucket struct {
	data map[string]item
	idx  rune
	mu   sync.RWMutex
}

type FileCache struct {
	buckets map[rune]*bucket
	datadir string
}

func NewFileCache(datadir string) *FileCache {
	cache := &FileCache{
		buckets: make(map[rune]*bucket),
		datadir: datadir,
	}

	bucketIdx := make([]rune, 0)
	for r := '0'; r <= '9'; r++ {
		bucketIdx = append(bucketIdx, r)
		cache.buckets[r] = &bucket{
			data: make(map[string]item),
			idx:  r,
		}
	}

	for r := 'a'; r <= 'z'; r++ {
		bucketIdx = append(bucketIdx, r)
		cache.buckets[r] = &bucket{
			data: make(map[string]item),
			idx:  r,
		}
	}

	for _, i := range bucketIdx {
		cache.load(i)
	}
	for _, i := range bucketIdx {
		go cache.checkExpired(i)
	}
	return cache
}

func (c *FileCache) dump(bucket *bucket) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(bucket.data)
	if err != nil {
		log.Printf("[cache] cannot dump cache %s", err)
		return
	}

	dir := filepath.Join(c.datadir, "cache")
	err = os.MkdirAll(dir, os.ModePerm)
	if err != nil {
		log.Printf("[cache] cannot store cache %s", err)
		return
	}
	path := filepath.Join(dir, fmt.Sprintf("%c.bin", bucket.idx))

	fi, err := os.Create(path)
	if err != nil {
		log.Printf("[cache] cannot store cache %s", err)
		return
	}
	defer fi.Close()
	fi.Write(buf.Bytes())
}

func (c *FileCache) load(bucketIdx rune) {
	path := filepath.Join(c.datadir, "cache", fmt.Sprintf("%c.bin", bucketIdx))
	b, err := os.ReadFile(path)
	if err != nil {
		log.Printf("[cache] cannot read cache file %s", err)
		return
	}

	d := gob.NewDecoder(bytes.NewBuffer(b))
	err = d.Decode(&c.buckets[bucketIdx].data)
	if err != nil {
		log.Printf("[cache] cannot load cache %s", err)
	}
	log.Printf("[cache] bucket '%c' loaded items %d/%d",
		bucketIdx, len(c.buckets[bucketIdx].data), cacheMaxItemsPerBucket)
}

func (c *FileCache) checkExpired(bucketIdx rune) {
	for {

		s := make([]struct {
			k string
			t time.Time
		}, 0)

		bucket := c.buckets[bucketIdx]
		bucket.mu.Lock()
		for k, v := range bucket.data {
			if time.Now().After(v.Expires) {
				log.Printf("[cache] expired %s", k)
				delete(bucket.data, k)
			}
			s = append(s, struct {
				k string
				t time.Time
			}{k: k, t: v.Expires})
		}
		bucket.mu.Unlock()

		if len(bucket.data) > cacheMaxItemsPerBucket {
			sort.Slice(s, func(i, j int) bool {
				t1 := s[i].t
				t2 := s[j].t
				return t2.After(t1)
			})

			ei := len(s) - cacheMaxItemsPerBucket
			bucket.mu.Lock()
			for _, i := range s[:ei] {
				log.Printf("[cache] evicted %s", i.k)
				delete(bucket.data, i.k)
			}
			bucket.mu.Unlock()
		}

		bucket.mu.RLock()
		c.dump(bucket)
		bucket.mu.RUnlock()

		time.Sleep(cacheExpiredCheckInterval)
	}
}

func (c *FileCache) buildKey(q dns.Question) string {
	return fmt.Sprintf("%s_%d_%d", q.Name, q.Qtype, q.Qclass)
}

func (c *FileCache) getBucket(q dns.Question) *bucket {
	runes := []rune(q.Name)
	if len(runes) == 0 {
		return nil
	}
	idx := runes[0]
	return c.buckets[idx]
}

func (c *FileCache) Set(q dns.Question, m *dns.Msg) error {
	key := c.buildKey(q)
	bucket := c.getBucket(q)
	if bucket == nil {
		return fmt.Errorf("no bucket exists for %s", q.Name)
	}
	log.Printf("set value on bucket %c", bucket.idx)

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

	bucket.mu.Lock()
	defer bucket.mu.Unlock()

	bucket.data[key] = item{
		Expires: expireTime,
		Msg:     packed,
	}
	return nil
}

func (c *FileCache) Get(q dns.Question) (*dns.Msg, error) {
	key := c.buildKey(q)
	bucket := c.getBucket(q)

	if bucket == nil {
		return nil, fmt.Errorf("no bucket exists for %s", q.Name)
	}

	log.Printf("get value from bucket %c", bucket.idx)

	bucket.mu.RLock()
	defer bucket.mu.RUnlock()

	if val, ok := bucket.data[key]; ok {
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
