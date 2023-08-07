package forward

import (
	"fmt"
	"math/rand"
)

var (
	letters = []string{
		"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m",
	}

	rootNS = []string{}
)

func init() {
	for _, l := range letters {
		rootNS = append(rootNS, fmt.Sprintf("%s.root-servers.net.", l))
	}
}

func getRootNS() string {
	n := rand.Intn(len(letters))
	return rootNS[n]
}
