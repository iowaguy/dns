package dns

import (
	"testing"
)

func TestCopyDNSSEC(t *testing.T) {
	sig := &Signature{
		length: 1,
		algorithm: 1,
		ttl: 1,
		expires: 1,
		begins: 1,
		key_tag: 1,
		signature: "123",
	}
	dnskey_rdata := &DNSKEY_Rdata{
		flags: 1,
		protocol: 1,
		algorithm: 1,
		public_key: "abc",
	}
	key := &Key{length: 1, []DNSKEY_Rdata{*dnskey_rdata}}
	entry := &Entering{
		length: 1,
		zType: EnteringType,
		entry_key_index: 1,
		key_sig: *sig,
		num_keys: 1,
		keys: []Key{*key},
	}
	exit := &Leaving{
		length: 1,
		zType: LeavingType,
		next_name: "123",
		rrtype: RRType(TypeTXT),
		rrsig: *sig,
	}
	zp := &ZonePair{
		entry: *entry,
		exit: *exit,
	}

	rrs := []RR{*zp}

	for _, rr := range rrs {
		rr1 := rr.copy()
		if rr.String() != rr1.String() {
			t.Fatalf("copy() failed %s != %s", rr.String(), rr1.String())
		}
	}
}
