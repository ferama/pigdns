package utils

import "testing"

func TestIsAddrDenied(t *testing.T) {
	denyNets := []string{
		"172.17.0.0/16",
		"192.168.15.0/24",
	}
	addrDenied := []string{"172.17.0.2"}
	addrAllowed := []string{"192.168.10.1", "127.0.0.1"}

	for _, a := range addrDenied {
		r, err := IsAddrInNetwork(a, denyNets)
		if err != nil {
			t.Fatal(err)
		}
		if r != true {
			t.Fatalf("expected %s to be denied", a)
		}
	}

	for _, a := range addrAllowed {
		r, err := IsAddrInNetwork(a, denyNets)
		if err != nil {
			t.Fatal(err)
		}
		if r == true {
			t.Fatalf("expected %s to be allowed", a)
		}
	}

}
