package cache

import (
	"time"
	"unsafe"
)

type Item struct {
	// when the item Expires
	Expires time.Time
	Data    []byte
}

// Sets the Expires field more conveniently
func (i *Item) SetTTL(ttl time.Duration) {
	i.Expires = time.Now().Add(ttl)
}

func (i *Item) SizeOf() uint64 {
	return uint64(unsafe.Sizeof(i.Expires)) +
		uint64(unsafe.Sizeof(i.Data)) +
		uint64(unsafe.Sizeof(i))
}

type Cache interface {
	// Get item from cache
	Get(key string) (*Item, error)

	// Set item to cache
	Set(key string, value *Item, ttl time.Duration) error
}
