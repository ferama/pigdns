package cache

import "github.com/miekg/dns"

type Cache interface {
	// Get item from cache
	Get(q dns.Question) (*dns.Msg, error)

	// Set item to cache
	Set(q dns.Question, m *dns.Msg) error
}
