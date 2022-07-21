package dns

// func (rr *ZonePair) copy() RR {
// 	return &ZonePair{copyEntering(rr.entry), copyLeaving(rr.exit)}
// }

// func (rr *DNSSECProof) copy() RR {
// 	return &DNSSECProof{rr.Hdr, copyIP(rr.A)}
// }

// func (rr *ZoneRecType) copy() RR {
// 	return &ZoneRecType{rr.Hdr, copyIP(rr.A)}
// }

func (rr *Signature) copy() RR {
	return &Signature{}
	// return Signature{rr.Hdr, copyIP(rr.A)}
}

// func (rr *Key) copy() RR {
// 	return &Key{rr.Hdr, copyIP(rr.A)}
// }

// func (rr *Entering) copy() RR {
// 	return &Entering{rr.Hdr, copyIP(rr.A)}
// }

// func (rr *SerialDS) copy() RR {
// 	return &SerialDS{rr.Hdr, copyIP(rr.A)}
// }

// func (rr *RRType) copy() RR {
// 	return &RRType{rr.Hdr, copyIP(rr.A)}
// }

// func (rr *Leaving) copy() RR {
// 	return &Leaving{rr.Hdr, copyIP(rr.A)}
// }

// func (rr *LeavingCNAME) copy() RR {
// 	return &LeavingCNAME{rr.Hdr, copyIP(rr.A)}
// }

// func (rr *LeavingDNAME) copy() RR {
// 	return &LeavingDNAME{rr.Hdr, copyIP(rr.A)}
// }
// func (rr *LeavingDS) copy() RR {
// 	return &LeavingDS{rr.Hdr, copyIP(rr.A)}
// }
// func (rr *LeavingOther) copy() RR {
// 	return &LeavingOther{rr.Hdr, copyIP(rr.A)}
// }
// func (rr *RRData) copy() RR {
// 	return &RRData{rr.Hdr, copyIP(rr.A)}
// }


func copyEntering(entry Entering) Entering {
	return Entering{}
	// keys := make([]Key, entry.num_keys)
	// for i, e := range entry.keys {
	// 	keys[i] = e.copy()
	// }
	// return Entering{entry.length, entry.zType, entry.entry_key_index, copySignature(entry.key_sig), entry.num_keys, keys}
}
