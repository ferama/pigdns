package cache

import (
	"time"
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

type Cache interface {
	// Get item from cache
	Get(key string) (*Item, error)

	// Set item to cache
	Set(key string, value *Item) error
}
