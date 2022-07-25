package dns

import (
	"testing"
)

func mockDNSSECProof() *DNSSECProof {
	sig := &Signature{
		length:    1,
		algorithm: 1,
		ttl:       1,
		expires:   1,
		begins:    1,
		key_tag:   1,
		signature: []byte("123"),
	}
	dnskey_rdata := &DNSKEY_Rdata{
		flags:      1,
		protocol:   1,
		algorithm:  1,
		public_key: []byte("abc"),
	}
	key := &Key{1, []DNSKEY_Rdata{*dnskey_rdata}}
	entry := &Entering{
		length:          1,
		zType:           EnteringType,
		entry_key_index: 1,
		key_sig:         *sig,
		num_keys:        1,
		keys:            []Key{*key},
	}
	exit := &Leaving{
		length:    1,
		zType:     LeavingType,
		next_name: "example.com",
		rrtype:    RRType(TypeTXT),
		rrsig:     *sig,
	}
	zp := &ZonePair{
		entry: *entry,
		exit:  *exit,
	}

	return &DNSSECProof{0, 1, []ZonePair{*zp}}
}

func TestCopyDNSSEC(t *testing.T) {
	proof := mockDNSSECProof()
	proofCopy := proof.copy()
	if proof.String() != proofCopy.String() {
		t.Fatalf("copy() failed %s != %s", proof.String(), proofCopy.String())
	}
}

// func TestPackUnpackDNSSEC(t *testing.T) {
// 	proof := mockDNSSECProof()
// 	proof.pack(, off int, compression compressionMap, compress bool)
// }
//
func TestLengthDNSSEC(t *testing.T) {
	proof := mockDNSSECProof()
	compression := make(map[string]struct{})

	l := proof.len(0, compression)

	if l != 77 {
		t.Fatalf("len() failed %d != 77", l)
	}
}
