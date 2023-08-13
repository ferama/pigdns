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

	"github.com/cespare/xxhash/v2"
	"github.com/ferama/pigdns/pkg/worker"

	"github.com/rs/zerolog/log"
)

const (
	cacheExpiredCheckInterval = 10 * time.Second
	cacheDumpInterval         = 60 * time.Second

	cacheMaxItemsPerBucket = 10000
	cacheNumBuckets        = 256
	cacheSubDir            = "cache"

	// this worker are go routines that do jobs like check for record expiration,
	// cahce dumps to disk and so on
	cacheMaxWorkers = 5
)

type bucket struct {
	data map[string]*Item

	idx uint64
	mu  sync.RWMutex
}

type FileCache struct {
	buckets map[uint64]*bucket
	datadir string

	workerPool *worker.Pool
}

func NewFileCache(datadir string) *FileCache {
	cache := &FileCache{
		buckets:    make(map[uint64]*bucket),
		datadir:    datadir,
		workerPool: worker.NewPool(cacheMaxWorkers),
	}

	var i uint64
	for i = 0; i <= cacheNumBuckets; i++ {
		cache.buckets[i] = &bucket{
			data: make(map[string]*Item),
			idx:  i,
		}
		cache.load(i)
	}

	go cache.setupJobs()

	return cache
}

func (c *FileCache) setupJobs() {
	expiredTicker := time.NewTicker(cacheExpiredCheckInterval)
	dumpTicker := time.NewTicker(cacheDumpInterval)
	for {
		select {
		case <-expiredTicker.C:
			var i uint64
			for i = 0; i <= cacheNumBuckets; i++ {
				// this is needed to be sure that the value of i doesn't change
				// while is read from the checkExpired function
				n := i

				// check expired
				c.workerPool.Enqueue(func() {
					c.checkExpiredJob(n)
				})
			}
		case <-dumpTicker.C:
			var i uint64
			for i = 0; i <= cacheNumBuckets; i++ {
				// this is needed to be sure that the value of i doesn't change
				// while is read from the checkExpired function
				n := i
				// dump cache to disk
				c.workerPool.Enqueue(func() {
					c.dumpJob(n)
				})
			}
		}
	}
}

func (c *FileCache) dumpJob(bucketIdx uint64) {
	bucket := c.buckets[bucketIdx]

	// log.Printf("[cache] dumping bucket '%d' to disk", bucket.idx)

	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)

	bucket.mu.RLock()
	err := enc.Encode(bucket.data)
	if err != nil {
		log.Printf("[cache] cannot dump cache %s", err)
		bucket.mu.RUnlock()
		return
	}
	bucket.mu.RUnlock()

	dir := filepath.Join(c.datadir, cacheSubDir)
	err = os.MkdirAll(dir, os.ModePerm)
	if err != nil {
		log.Printf("[cache] cannot store cache %s", err)
		return
	}
	path := filepath.Join(dir, fmt.Sprintf("%d.bin", bucket.idx))

	fi, err := os.Create(path)
	if err != nil {
		log.Printf("[cache] cannot store cache %s", err)
		return
	}
	defer fi.Close()
	fi.Write(buf.Bytes())
}

func (c *FileCache) load(bucketIdx uint64) {
	path := filepath.Join(c.datadir, cacheSubDir, fmt.Sprintf("%d.bin", bucketIdx))
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
	log.Printf("[cache] bucket '%d' loaded items %d/%d",
		bucketIdx, len(c.buckets[bucketIdx].data), cacheMaxItemsPerBucket)
}

func (c *FileCache) checkExpiredJob(bucketIdx uint64) {
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
}

func (c *FileCache) getBucket(key string) *bucket {
	h := xxhash.Sum64String(key)
	bucketID := h % cacheNumBuckets
	return c.buckets[bucketID]
}

func (c *FileCache) Set(key string, value *Item) error {
	bucket := c.getBucket(key)
	if bucket == nil {
		return fmt.Errorf("no bucket exists for %s", key)
	}

	bucket.mu.Lock()
	bucket.data[key] = value
	bucket.mu.Unlock()

	return nil
}

func (c *FileCache) Get(key string) (*Item, error) {
	bucket := c.getBucket(key)
	if bucket == nil {
		return nil, fmt.Errorf("no bucket exists for %s", key)
	}

	bucket.mu.RLock()
	defer bucket.mu.RUnlock()

	if val, ok := bucket.data[key]; ok {
		return val, nil
	}
	return nil, errors.New("item not found")
}
