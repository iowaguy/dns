package dns

import (
	"testing"
)

func mockDNSSECProof() *DNSSECProof {
	sig := &Signature{
		Length:    21,
		Algorithm: 1,
		Labels:    1,
		Ttl:       1,
		Expires:   1,
		Begins:    1,
		Key_tag:   1,
		Signature: []byte("123"),
	}
	key := &Key{
		Length:     9,
		Flags:      1,
		Protocol:   1,
		Algorithm:  1,
		Public_key: []byte("abc"),
	}
	entry := &Entering{
		Length:          37,
		ZType:           EnteringType,
		Entry_key_index: 1,
		Key_sig:         *sig,
		Num_keys:        1,
		Keys:            []Key{*key},
	}
	exit := &Leaving{
		Length:    38,
		ZType:     LeavingType,
		Next_name: "example.com.",
		Rrtype:    RRType(TypeTXT),
		Rrsig:     *sig,
	}
	zp := &ZonePair{
		Entry: *entry,
		Exit:  *exit,
	}

	return &DNSSECProof{
		Initial_key_tag: 9,
		Num_zones:       1,
		Zones:           []ZonePair{*zp},
	}
}

func TestCopyDNSSEC(t *testing.T) {
	proof := mockDNSSECProof()
	proofCopy := proof.copy()
	if proof.String() != proofCopy.String() {
		t.Fatalf("copy() failed %s != %s", proof.String(), proofCopy.String())
	}
}

func TestPackUnpackDNSSEC(t *testing.T) {
	proof := mockDNSSECProof()
	compression := make(map[string]struct{})
	packedBuf := make([]byte, proof.len(0, compression))
	compressionM := make(map[string]uint16)
	off, err := proof.pack(packedBuf, 0, compressionMap{int: compressionM}, false)
	if err != nil {
		t.Fatalf("pack() failed at offset %d\n", off)
	}

	newProof := &DNSSECProof{}
	off, err = newProof.unpack(packedBuf, 0)
	if err != nil {
		t.Fatalf("unpack() failed at offset %d\n", off)
	}
	if proof.String() != newProof.String() {
		t.Fatalf("unpack() failed %s != %s", proof.String(), newProof.String())
	}
}

func TestLengthDNSSEC(t *testing.T) {
	proof := mockDNSSECProof()
	compression := make(map[string]struct{})

	l := proof.len(0, compression)

	if l != 77 {
		t.Fatalf("len() failed %d != 77", l)
	}
}
