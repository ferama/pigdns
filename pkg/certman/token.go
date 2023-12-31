package certman

import (
	"sync"
)

var (
	once     sync.Once
	instance *token
)

// Token returns a singleton instance of Token
func Token() *token {
	once.Do(func() {
		instance = newToken()
	})

	return instance
}

type token struct {
	mu sync.Mutex

	value string
}

func newToken() *token {
	t := &token{
		value: "",
	}
	return t
}

func (t *token) Set(v string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.value = v
}

func (t *token) Get() string {
	t.mu.Lock()
	defer t.mu.Unlock()

	return t.value
}
