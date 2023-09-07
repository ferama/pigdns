package oneinflight

import "sync"

type Worker func(params ...any) any

type OneInFlight struct {
	mu      sync.Mutex
	lockmap map[string]*sync.Mutex
}

func New() *OneInFlight {
	o := &OneInFlight{
		lockmap: make(map[string]*sync.Mutex),
	}
	return o
}

func (o *OneInFlight) Run(key string, worker Worker, params ...any) any {
	var emu *sync.Mutex

	// get or create a new mutex for the  key in a thread
	// safe way
	o.mu.Lock()
	if tmp, ok := o.lockmap[key]; ok {
		emu = tmp
	} else {
		emu = new(sync.Mutex)
		o.lockmap[key] = emu
	}
	o.mu.Unlock()

	// no more then one concurrent worker running for the given cache key, so
	// I'm taking the lock here
	emu.Lock()
	// cleanup the lockmap at the end and unlock
	defer func() {
		o.mu.Lock()
		defer o.mu.Unlock()

		delete(o.lockmap, key)
		emu.Unlock()
	}()

	return worker(params...)
}
