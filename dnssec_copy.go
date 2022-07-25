package dns

import "strings"

func (rr *ZonePair) copy() RR {
	return *copyZonePair(rr)
}

func (rr *DNSSECProof) copy() RR {
	zonePairs := make([]ZonePair, len(rr.zones))
	for i, z := range rr.zones {
		zonePairs[i] = *copyZonePair(&z)
	}
	return &DNSSECProof{
		rr.initial_key_tag,
		rr.num_zones,
		zonePairs,
	}
}

func (rr *Signature) copy() RR {
	return copySignature(rr)
}

func (rr *Key) copy() RR {
	dnskeysRdata := make([]DNSKEY_Rdata, len(rr.rdata))
	for i, dk := range rr.rdata {
		dnskeysRdata[i] = *copyDataDNSKEY_Rdata(&dk)
	}
	return &Key{rr.numRdatas, dnskeysRdata}
}

func (rr *Entering) copy() RR {
	return copyEntering(rr)
}

func (rr *SerialDS) copy() RR {
	return copyDataSerialDS(rr)
}

func (rr *Leaving) copy() RR {
	return copyLeaving(rr)
}

func (rr *LeavingCNAME) copy() RR {
	return copyLeavingCNAME(rr)
}

func (rr *LeavingDNAME) copy() RR {
	return &LeavingDNAME{
		*copyLeavingCNAME(&rr.LeavingCNAME),
	}
}

func (rr *LeavingDS) copy() RR {
	dsRecords := make([]SerialDS, len(rr.ds_records))
	for i, ds := range rr.ds_records {
		dsRecords[i] = *copyDataSerialDS(&ds)
	}
	return &LeavingDS{
		*copyLeaving(&rr.Leaving),
		rr.num_ds,
		dsRecords,
	}
}

func (rr *LeavingOther) copy() RR {
	rrs := make([]RRData, len(rr.rrs))
	for i, r := range rr.rrs {
		rrs[i] = *copyDataRRData(&r)
	}
	return &LeavingOther{
		*copyLeaving(&rr.Leaving),
		rr.num_rrs,
		rrs,
	}
}

func (rr *RRData) copy() RR {
	return copyDataRRData(rr)
}

func (rr *DNSKEY_Rdata) copy() RR {
	return copyDataDNSKEY_Rdata(rr)
}

func copyDataDNSKEY_Rdata(rr *DNSKEY_Rdata) *DNSKEY_Rdata {
	newPubKey := make([]byte, len(rr.public_key))
	copy(newPubKey, rr.public_key)
	return &DNSKEY_Rdata{
		rr.length,
		rr.flags,
		rr.protocol,
		rr.algorithm,
		newPubKey,
	}
}

func copyEntering(entry *Entering) *Entering {
	newKeys := entry.keys
	return &Entering{
		entry.length,
		entry.zType,
		entry.entry_key_index,
		*copySignature(&entry.key_sig),
		entry.num_keys,
		newKeys,
	}
}

func copyLeaving(exit *Leaving) *Leaving {
	return &Leaving{
		exit.length,
		exit.zType,
		Name(strings.Clone(exit.next_name.String())),
		exit.rrtype,
		*copySignature(&exit.rrsig),
	}
}

func copySignature(sig *Signature) *Signature {
	newSig := make([]byte, len(sig.signature))
	copy(newSig, sig.signature)
	return &Signature{
		sig.length,
		sig.algorithm,
		sig.labels,
		sig.ttl,
		sig.expires,
		sig.begins,
		sig.key_tag,
		newSig,
	}
}

func copyZonePair(zp *ZonePair) *ZonePair {
	return &ZonePair{
		*copyEntering(&zp.entry),
		*copyLeaving(&zp.exit),
	}
}

func copyLeavingCNAME(l *LeavingCNAME) *LeavingCNAME {
	return &LeavingCNAME{
		*copyLeaving(&l.Leaving),
		Name(strings.Clone(l.name.String())),
	}
}

func copyDataSerialDS(s *SerialDS) *SerialDS {
	newDigest := make([]byte, len(s.digest))
	copy(newDigest, s.digest)
	return &SerialDS{
		s.length,
		s.key_tag,
		s.algorithm,
		s.digest_type,
		s.digest_len,
		newDigest,
	}
}

func copyDataRRData(rrdata *RRData) *RRData {
	newRRData := make([]byte, len(rrdata.rrdata))
	copy(newRRData, rrdata.rrdata)
	return &RRData{rrdata.length, newRRData}
}
