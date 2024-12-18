package cache

import (
	"bytes"
	"encoding/gob"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/cespare/xxhash/v2"
	"github.com/ferama/pigdns/pkg/metrics"
	"github.com/ferama/pigdns/pkg/worker"

	"github.com/rs/zerolog/log"
)

const (
	cacheExpiredCheckInterval = 10 * time.Second
	cacheDumpInterval         = 5 * time.Minute
	cacheEvictionInterval     = 1 * time.Minute

	cacheNumBuckets = 128
	cacheSubDir     = "cache"
)

type bucket struct {
	sync.Mutex

	data map[string]*Item

	idx uint64
}

type FileCache struct {
	buckets map[uint64]*bucket
	datadir string

	maxItems int

	name string

	expireWorkerPool *worker.Pool
	evictWorkerPool  *worker.Pool
	dumpWorkerPool   *worker.Pool

	persistence bool
}

func NewFileCache(datadir string, name string, size int, cachePersistence bool) *FileCache {

	// allow a minimum
	maxItems := max(size, 1000)

	// this worker are go routines that do jobs like check for record expiration,
	// cache dumps to disk and so on
	workers := int(runtime.NumCPU() / 3)
	maxWorkers := max(1, workers)

	cache := &FileCache{
		buckets:          make(map[uint64]*bucket),
		persistence:      cachePersistence,
		datadir:          datadir,
		name:             name,
		maxItems:         maxItems,
		expireWorkerPool: worker.NewPool(maxWorkers),
		evictWorkerPool:  worker.NewPool(maxWorkers),
		dumpWorkerPool:   worker.NewPool(maxWorkers),
	}

	var i uint64
	loaded := false
	for i = 0; i <= cacheNumBuckets; i++ {
		cache.buckets[i] = &bucket{
			data: make(map[string]*Item),
			idx:  i,
		}
		if cachePersistence {
			loaded = cache.load(i)
		}
	}
	if !loaded {
		log.Warn().Msg("no cache loaded from disk")
	}

	log.Info().
		Str("cache", name).
		Int("size", maxItems).
		Msg("cache started")

	go cache.setupJobs()

	return cache
}

func (c *FileCache) getCacheSize() int {

	var i uint64
	itemsCount := 0
	for i = 0; i <= cacheNumBuckets; i++ {
		bucket := c.buckets[i]
		bucket.Lock()
		itemsCount += len(bucket.data)
		bucket.Unlock()
	}

	m := metrics.Instance().GetCacheItemsCountMetric(c.name)
	if m != nil {
		m.Set(float64(itemsCount))
	}

	return itemsCount
}

func (c *FileCache) setupJobs() {

	// Expire JOB
	go func() {
		for {
			time.Sleep(cacheExpiredCheckInterval)

			c.getCacheSize()

			// t := time.Now()
			// log.Printf("[%s cache] expire job started", c.name)
			var i uint64
			for i = 0; i <= cacheNumBuckets; i++ {
				// this is needed to be sure that the value of i doesn't change
				// while is read from the checkExpired function
				n := i

				// check expired
				c.expireWorkerPool.Enqueue(func() {
					c.expireJob(n)
				})
			}

			c.expireWorkerPool.Wait()
			// log.Printf("[%s cache] expire job ended. took %s", c.name, time.Since(t))
		}
	}()

	// Evict JOB
	go func() {
		for {
			log.Debug().
				Str("name", c.name).
				Int("size", c.getCacheSize()).
				Int("capacity", c.maxItems).
				Msg("[cache]")

			time.Sleep(cacheEvictionInterval)
			var i uint64
			for i = 0; i <= cacheNumBuckets; i++ {
				// this is needed to be sure that the value of i doesn't change
				// while is read from the checkExpired function
				n := i
				// dump cache to disk
				c.evictWorkerPool.Enqueue(func() {
					c.evictJob(n)
				})
			}
			c.evictWorkerPool.Wait()
		}
	}()

	if c.persistence {
		// Dump JOB
		go func() {
			for {
				time.Sleep(cacheDumpInterval)

				// t := time.Now()
				// log.Printf("[%s cache] dump job started", c.name)
				var i uint64
				for i = 0; i <= cacheNumBuckets; i++ {
					// this is needed to be sure that the value of i doesn't change
					// while is read from the checkExpired function
					n := i
					// dump cache to disk
					c.dumpWorkerPool.Enqueue(func() {
						c.dumpJob(n)
					})
				}
				c.dumpWorkerPool.Wait()
				// log.Printf("[%s cache] dump job ended. took %s", c.name, time.Since(t))
			}
		}()
	}
}

func (c *FileCache) dumpJob(bucketIdx uint64) {
	// disable persistence if we don't have a datadir
	if c.datadir == "" {
		log.Warn().Msg("no datadir. not persisting cache")
		return
	}

	bucket := c.buckets[bucketIdx]

	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)

	bucket.Lock()
	err := enc.Encode(bucket.data)
	if err != nil {
		log.Printf("[%s cache] cannot dump cache %s", c.name, err)
		bucket.Unlock()
		return
	}
	bucket.Unlock()

	dir := filepath.Join(c.datadir, cacheSubDir)
	err = os.MkdirAll(dir, os.ModePerm)
	if err != nil {
		log.Printf("[%s cache] cannot store cache %s", c.name, err)
		return
	}
	path := filepath.Join(dir, fmt.Sprintf("%d.bin", bucket.idx))

	fi, err := os.Create(path)
	if err != nil {
		log.Printf("[%s cache] cannot store cache %s", c.name, err)
		return
	}
	defer fi.Close()
	fi.Write(buf.Bytes())
}

func (c *FileCache) load(bucketIdx uint64) bool {
	// disable persistence if we don't have a datadir
	if c.datadir == "" {
		return false
	}

	path := filepath.Join(c.datadir, cacheSubDir, fmt.Sprintf("%d.bin", bucketIdx))
	b, err := os.ReadFile(path)
	if err != nil {
		// log.Printf("[%s cache] cannot read cache file %s", c.name, err)
		return false
	}

	d := gob.NewDecoder(bytes.NewBuffer(b))
	err = d.Decode(&c.buckets[bucketIdx].data)
	return err == nil
}

func (c *FileCache) evictJob(bucketIdx uint64) {
	s := make([]struct {
		key     string
		expires time.Time
	}, 0)

	bucket := c.buckets[bucketIdx]

	bucket.Lock()
	for k, v := range bucket.data {
		s = append(s, struct {
			key     string
			expires time.Time
		}{key: k, expires: v.Expires})
	}

	maxBucketSize := c.maxItems / cacheNumBuckets
	bucketSize := len(bucket.data)
	bucket.Unlock()

	// if bucketSize is greater than maxBucketSize
	// drop its size by half evicting the closest to expire items
	if bucketSize > maxBucketSize {
		sort.Slice(s, func(i, j int) bool {
			t1 := s[i].expires
			t2 := s[j].expires
			return t2.After(t1)
		})
		half := int(len(s) / 2)
		for _, i := range s[:half] {
			log.Info().
				Str("name", c.name).
				Str("key", i.key).
				Msg("[cache] evicted")

			bucket.Lock()
			delete(bucket.data, i.key)
			bucket.Unlock()
		}
	}
}

func (c *FileCache) expireJob(bucketIdx uint64) {
	bucket := c.buckets[bucketIdx]
	bucket.Lock()
	defer bucket.Unlock()

	for k, v := range bucket.data {
		if time.Now().After(v.Expires) {
			// log.Printf("[%s cache] expired %s", c.name, k)
			delete(bucket.data, k)
		}
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

	bucket.Lock()
	bucket.data[key] = value
	bucket.Unlock()

	return nil
}

func (c *FileCache) Get(key string) (*Item, error) {
	bucket := c.getBucket(key)
	if bucket == nil {
		return nil, fmt.Errorf("no bucket exists for %s", key)
	}

	bucket.Lock()
	defer bucket.Unlock()

	if val, ok := bucket.data[key]; ok {
		return val, nil
	}
	return nil, errors.New("item not found")
}
