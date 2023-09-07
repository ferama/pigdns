package oneinflight

import (
	"fmt"
	"math/rand"
	"sync"
	"testing"
	"time"
)

func TestOneInFlight(t *testing.T) {
	oif := New()

	var wg sync.WaitGroup

	worker := func(params ...any) any {
		name := params[0].(string)

		t := 1 * time.Second
		fmt.Printf("%s sleeping: %s\n", name, t)
		time.Sleep(t)
		return rand.Intn(10)
	}

	i := 5
	for i > 0 {
		i--
		wg.Add(1)
		go func() {
			res := oif.Run("key1", worker, "worker1")
			fmt.Printf("worker1 res: %d\n", res)
			wg.Done()
		}()
		wg.Add(1)
		go func() {
			res := oif.Run("key2", worker, "worker2")
			fmt.Printf("worker2 res: %d\n", res)
			wg.Done()
		}()
	}

	wg.Wait()
}
