package dns

func (rr *ZonePair) len(off int, compression map[string]struct{}) int {
	l := rr.entry.len(0, compression)
	l += rr.exit.len(0, compression)
	return l
}

func (rr *DNSSECProof) len(off int, compression map[string]struct{}) int {
	l := 2 // initial_key_tag
	l += 1 // num_zones

	for _, z := range rr.zones {
		l += z.len(0, compression)
	}
	return l
}

func (rr *Signature) len(off int, compression map[string]struct{}) int {
	l := 2 // length
	l += 1 // algorithm
	l += 1 // labels
	l += 4 // ttl
	l += 4 // expires
	l += 4 // begins
	l += 2 // key_tag
	l += len(rr.signature)
	return l
}

func (rr *Key) len(off int, compression map[string]struct{}) int {
	l := 2 // length
	for _, d := range rr.rdata {
		l += d.len(l, compression)
	}
	return l
}

func (rr *Entering) len(off int, compression map[string]struct{}) int {
	l := 2 // length
	l += 1 // zType
	l += 1 // entry_key_index
	l += rr.key_sig.len(l, compression)
	l += 1 // num_keys

	for _, k := range rr.keys {
		l += k.len(l, compression)
	}
	return l
}

func (rr *SerialDS) len(off int, compression map[string]struct{}) int {
	l := 2 // key_tag
	l += 1 // algorithm
	l += 1 // digest_type
	l += 2 // digest_len
	l += len(rr.digest)
	return l
}

func (rr *Leaving) len(off int, compression map[string]struct{}) int {
	l := 2 // length
	l += 1 // zType

  // don't need to add 1, because we are not including the
  // string "len" field in the serialization.
	l += len(rr.next_name)
	l += 2 // rrtype
	l += rr.rrsig.len(l, compression)
	return l
}

func (rr *LeavingCNAME) len(off int, compression map[string]struct{}) int {
	l := rr.Leaving.len(0, compression)

  // don't need to add 1, because we are not including the
  // string "len" field in the serialization.
	l += len(rr.next_name)
	return l
}

func (rr *LeavingDNAME) len(off int, compression map[string]struct{}) int {
	return rr.LeavingCNAME.len(0, compression)
}

func (rr *LeavingDS) len(off int, compression map[string]struct{}) int {
	l := rr.Leaving.len(0, compression)
	l += 1 // num_ds

	for _, ds := range rr.ds_records {
		l += ds.len(0, compression)
	}
	return l
}

func (rr *LeavingOther) len(off int, compression map[string]struct{}) int {
	l := rr.Leaving.len(0, compression)
	l += 1 // num_rrs

	for _, r := range rr.rrs {
		l += r.len(0, compression)
	}
	return l
}

func (rr *RRData) len(off int, compression map[string]struct{}) int {
	l := 2 // length
	l += len(rr.rrdata)
	return l
}

func (rr *DNSKEY_Rdata) len(off int, compression map[string]struct{}) int {
	l := 2 // flags
	l += 1 // protocol
	l += 1 // algorithm
	l += len(rr.public_key)
	return l
}
