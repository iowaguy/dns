package dns

import (
	"testing"
)

func TestCopyDNSSEC(t *testing.T) {
	rrs := []RR{
		&Signature{
			length: 1,
			algorithm: 1,
			ttl: 1,
			expires: 1,
			begins: 1,
			key_tag: 1,
			signature: "123",
		},
	}

	for _, rr := range rrs {
		rr1 := rr.copy()
		if rr.String() != rr1.String() {
			t.Fatalf("copy() failed %s != %s", rr.String(), rr1.String())
		}
	}
}
