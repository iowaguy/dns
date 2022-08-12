package dns

import "strings"

func (rr *ZonePair) copy() RR {
	return copyZonePair(rr)
}

func (rr *DNSSECProof) copy() RR {
	zonePairs := make([]ZonePair, len(rr.Zones))
	for i, z := range rr.Zones {
		zonePairs[i] = *copyZonePair(&z)
	}
	return &DNSSECProof{
		rr.Initial_key_tag,
		rr.Num_zones,
		zonePairs,
	}
}

func (rr *Signature) copy() RR {
	return copySignature(rr)
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
	dsRecords := make([]SerialDS, len(rr.Ds_records))
	for i, ds := range rr.Ds_records {
		dsRecords[i] = *copyDataSerialDS(&ds)
	}
	return &LeavingDS{
		*copyLeaving(&rr.Leaving),
		rr.Num_ds,
		dsRecords,
	}
}

func (rr *LeavingOther) copy() RR {
	rrs := make([]RRData, len(rr.Rrs))
	for i, r := range rr.Rrs {
		rrs[i] = *copyDataRRData(&r)
	}
	return &LeavingOther{
		*copyLeaving(&rr.Leaving),
		rr.Num_rrs,
		rrs,
	}
}

func (rr *RRData) copy() RR {
	return copyDataRRData(rr)
}

func (rr *Key) copy() RR {
	return copyDataKey(rr)
}

func copyDataKey(rr *Key) *Key {
	newPubKey := make([]byte, len(rr.Public_key))
	copy(newPubKey, rr.Public_key)
	return &Key{
		rr.Length,
		rr.Flags,
		rr.Protocol,
		rr.Algorithm,
		newPubKey,
	}
}

func copyEntering(entry *Entering) *Entering {
	newKeys := entry.Keys
	return &Entering{
		entry.Length,
		entry.ZType,
		entry.Entry_key_index,
		*copySignature(&entry.Key_sig),
		entry.Num_keys,
		newKeys,
	}
}

func copyLeaving(exit *Leaving) *Leaving {
	return &Leaving{
		exit.Length,
		exit.ZType,
		Name(strings.Clone(exit.Next_name.String())),
		exit.Rrtype,
		*copySignature(&exit.Rrsig),
	}
}

func copySignature(sig *Signature) *Signature {
	newSig := make([]byte, len(sig.Signature))
	copy(newSig, sig.Signature)
	return &Signature{
		sig.Length,
		sig.Algorithm,
		sig.Labels,
		sig.Ttl,
		sig.Expires,
		sig.Begins,
		sig.Key_tag,
		newSig,
	}
}

func copyZonePair(zp *ZonePair) *ZonePair {
	return &ZonePair{
		*copyEntering(&zp.Entry),
		*copyLeaving(&zp.Exit),
	}
}

func copyLeavingCNAME(l *LeavingCNAME) *LeavingCNAME {
	return &LeavingCNAME{
		*copyLeaving(&l.Leaving),
		Name(strings.Clone(l.Name.String())),
	}
}

func copyDataSerialDS(s *SerialDS) *SerialDS {
	newDigest := make([]byte, len(s.Digest))
	copy(newDigest, s.Digest)
	return &SerialDS{
		s.Length,
		s.Key_tag,
		s.Algorithm,
		s.Digest_type,
		s.Digest_len,
		newDigest,
	}
}

func copyDataRRData(rrdata *RRData) *RRData {
	newRRData := make([]byte, len(rrdata.Rrdata))
	copy(newRRData, rrdata.Rrdata)
	return &RRData{rrdata.Length, newRRData}
}
