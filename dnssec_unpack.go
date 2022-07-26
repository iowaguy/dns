package dns

func (rr *Signature) unpack(msg []byte, off int) (off1 int, err error) {
	rdStart := off
	_ = rdStart

	*rr, off, err = unpackDataSignature(msg, off)
	if err != nil {
		return off, err
	}
	return off, nil
}

func (rr *DNSKEY_Rdata) unpack(msg []byte, off int) (off1 int, err error) {
	rdStart := off
	_ = rdStart

	*rr, off, err = unpackDataDNSKEY_Rdata(msg, off)
	if err != nil {
		return off, err
	}
	return off, nil
}

func (rr *SerialDS) unpack(msg []byte, off int) (off1 int, err error) {
	rdStart := off
	_ = rdStart

	*rr, off, err = unpackDataSerialDS(msg, off)
	if err != nil {
		return off, err
	}
	return off, nil
}

func (rr *RRData) unpack(msg []byte, off int) (off1 int, err error) {
	rdStart := off
	_ = rdStart

	*rr, off, err = unpackDataRRData(msg, off)
	if err != nil {
		return off, err
	}
	return off, nil
}

func (rr *Key) unpack(msg []byte, off int) (off1 int, err error) {
	rdStart := off
	_ = rdStart

	*rr, off, err = unpackDataKey(msg, off)
	if err != nil {
		return off, err
	}
	return off, nil
}

func (rr *Entering) unpack(msg []byte, off int) (off1 int, err error) {
	rdStart := off
	_ = rdStart

	*rr, off, err = unpackDataEntering(msg, off)
	if err != nil {
		return off, err
	}
	return off, nil
}

func (rr *Leaving) unpack(msg []byte, off int) (off1 int, err error) {
	rdStart := off
	_ = rdStart

	*rr, off, err = unpackDataLeaving(msg, off)
	if err != nil {
		return off, err
	}
	return off, nil
}

func (rr *LeavingCNAME) unpack(msg []byte, off int) (off1 int, err error) {
	rdStart := off
	_ = rdStart

	*rr, off, err = unpackDataLeavingCNAME(msg, off)
	if err != nil {
		return off, err
	}
	return off, nil
}

func (rr *LeavingDNAME) unpack(msg []byte, off int) (off1 int, err error) {
	rdStart := off
	_ = rdStart

	(*rr).LeavingCNAME, off, err = unpackDataLeavingCNAME(msg, off)
	if err != nil {
		return off, err
	}
	return off, nil
}

func (rr *LeavingDS) unpack(msg []byte, off int) (off1 int, err error) {
	rdStart := off
	_ = rdStart

	rr.Leaving, off, err = unpackDataLeaving(msg, off)
	if err != nil {
		return off, err
	}
	rr.num_ds, off, err = unpackUint8(msg, off)
	if err != nil {
		return off, err
	}

	for i := 0; i < int(rr.num_ds); i++ {
		rr.ds_records[i], off, err = unpackDataSerialDS(msg, off)
		if err != nil {
			return off, err
		}
	}
	return off, nil
}

func (rr *LeavingOther) unpack(msg []byte, off int) (off1 int, err error) {
	rdStart := off
	_ = rdStart

	rr.Leaving, off, err = unpackDataLeaving(msg, off)
	if err != nil {
		return off, err
	}
	rr.num_rrs, off, err = unpackUint8(msg, off)
	if err != nil {
		return off, err
	}

	for i := 0; i < int(rr.num_rrs); i++ {
		rr.rrs[i], off, err = unpackDataRRData(msg, off)
		if err != nil {
			return off, err
		}
	}
	return off, nil
}

func (rr *ZonePair) unpack(msg []byte, off int) (off1 int, err error) {
	rdStart := off
	_ = rdStart

	*rr, off, err = unpackDataZonePair(msg, off)
	if err != nil {
		return off, err
	}
	return off, nil
}

func (rr *DNSSECProof) unpack(msg []byte, off int) (off1 int, err error) {
	rdStart := off
	_ = rdStart

	rr.initial_key_tag, off, err = unpackUint16(msg, off)
	if err != nil {
		return off, err
	}
	rr.num_zones, off, err = unpackUint8(msg, off)
	if err != nil {
		return off, err
	}

	rr.zones = make([]ZonePair, rr.num_zones)
	for i := 0; i < int(rr.num_zones); i++ {
		rr.zones[i], off, err = unpackDataZonePair(msg, off)
		if err != nil {
			return off, err
		}
	}
	return off, nil
}

func unpackDataSignature(msg []byte, off int) (sig Signature, off1 int, err error) {
	rdStart := off

	sig = Signature{}
	if off == len(msg) {
		return sig, off, nil
	}

	sig.length, off, err = unpackUint16(msg, off)
	if err != nil {
		return sig, off, err
	}
	sig.algorithm, off, err = unpackUint8(msg, off)
	if err != nil {
		return sig, off, err
	}
	sig.labels, off, err = unpackUint8(msg, off)
	if err != nil {
		return sig, off, err
	}
	sig.ttl, off, err = unpackUint32(msg, off)
	if err != nil {
		return sig, off, err
	}
	sig.expires, off, err = unpackUint32(msg, off)
	if err != nil {
		return sig, off, err
	}
	sig.begins, off, err = unpackUint32(msg, off)
	if err != nil {
		return sig, off, err
	}
	sig.key_tag, off, err = unpackUint16(msg, off)
	if err != nil {
		return sig, off, err
	}
	sig.signature, off, err = unpackByteArray(msg, off, int(sig.length)-(off-rdStart))
	if err != nil {
		return sig, off, err
	}

	return sig, off, nil
}

func unpackByteArray(msg []byte, off int, length int) (b []byte, off1 int, err error) {
	b = make([]byte, length)
	copy(b, msg[off:off+length])
	return b, off + length, nil
}

func unpackDataDNSKEY_Rdata(msg []byte, off int) (dnskey_rdata DNSKEY_Rdata, off1 int, err error) {
	rdStart := off

	dnskey_rdata = DNSKEY_Rdata{}
	if off == len(msg) {
		return dnskey_rdata, off, nil
	}

	dnskey_rdata.length, off, err = unpackUint16(msg, off)
	if err != nil {
		return dnskey_rdata, off, err
	}
	dnskey_rdata.flags, off, err = unpackUint16(msg, off)
	if err != nil {
		return dnskey_rdata, off, err
	}
	dnskey_rdata.protocol, off, err = unpackUint8(msg, off)
	if err != nil {
		return dnskey_rdata, off, err
	}
	dnskey_rdata.algorithm, off, err = unpackUint8(msg, off)
	if err != nil {
		return dnskey_rdata, off, err
	}
	dnskey_rdata.public_key, off, err = unpackByteArray(msg, off, int(dnskey_rdata.length)-(off-rdStart))
	if err != nil {
		return dnskey_rdata, off, err
	}

	return dnskey_rdata, off, nil
}

func unpackDataSerialDS(msg []byte, off int) (ds SerialDS, off1 int, err error) {
	rdStart := off

	ds = SerialDS{}
	if off == len(msg) {
		return ds, off, nil
	}

	ds.length, off, err = unpackUint16(msg, off)
	if err != nil {
		return ds, off, err
	}
	ds.key_tag, off, err = unpackUint16(msg, off)
	if err != nil {
		return ds, off, err
	}
	ds.algorithm, off, err = unpackUint8(msg, off)
	if err != nil {
		return ds, off, err
	}
	ds.digest_type, off, err = unpackUint8(msg, off)
	if err != nil {
		return ds, off, err
	}
	ds.digest_len, off, err = unpackUint16(msg, off)
	if err != nil {
		return ds, off, err
	}
	ds.digest, off, err = unpackByteArray(msg, off, int(ds.length)-(off-rdStart))
	if err != nil {
		return ds, off, err
	}

	return ds, off, nil
}

func unpackDataRRData(msg []byte, off int) (rd RRData, off1 int, err error) {
	rdStart := off

	rd = RRData{}
	if off == len(msg) {
		return rd, off, nil
	}

	rd.length, off, err = unpackUint16(msg, off)
	if err != nil {
		return rd, off, err
	}
	rd.rrdata, off, err = unpackByteArray(msg, off, int(rd.length)-(off-rdStart))
	if err != nil {
		return rd, off, err
	}

	return rd, off, nil
}

func unpackDataKey(msg []byte, off int) (key Key, off1 int, err error) {
	key = Key{}
	if off == len(msg) {
		return key, off, nil
	}
	key.numRdatas, off, err = unpackUint16(msg, off)
	if err != nil {
		return key, off, err
	}

	key.rdata = make([]DNSKEY_Rdata, key.numRdatas)
	for i := 0; i < int(key.numRdatas); i++ {
		key.rdata[i], off, err = unpackDataDNSKEY_Rdata(msg, off)
		if err != nil {
			return key, off, err
		}
	}

	return key, off, nil
}

func unpackDataEntering(msg []byte, off int) (entry Entering, off1 int, err error) {
	entry = Entering{}
	if off == len(msg) {
		return entry, off, nil
	}
	entry.length, off, err = unpackUint16(msg, off)
	if err != nil {
		return entry, off, err
	}
	zType, off, err := unpackUint8(msg, off)
	if err != nil {
		return entry, off, err
	}
	entry.zType = ZoneRecType(zType)

	entry.entry_key_index, off, err = unpackUint8(msg, off)
	if err != nil {
		return entry, off, err
	}
	entry.key_sig, off, err = unpackDataSignature(msg, off)
	if err != nil {
		return entry, off, err
	}
	entry.num_keys, off, err = unpackUint8(msg, off)
	if err != nil {
		return entry, off, err
	}

	entry.keys = make([]Key, entry.num_keys)
	for i := 0; i < int(entry.num_keys); i++ {
		entry.keys[i], off, err = unpackDataKey(msg, off)
		if err != nil {
			return entry, off, err
		}
	}

	return entry, off, nil
}

func unpackDataLeaving(msg []byte, off int) (l Leaving, off1 int, err error) {
	l = Leaving{}
	if off == len(msg) {
		return l, off, nil
	}
	l.length, off, err = unpackUint16(msg, off)
	if err != nil {
		return l, off, err
	}
	zType, off, err := unpackUint8(msg, off)
	if err != nil {
		return l, off, err
	}
	l.zType = ZoneRecType(zType)

	next_name, off, err := UnpackDomainName(msg, off)
	if err != nil {
		return l, off, err
	}
	l.next_name = Name(next_name)

	rrtype, off, err := unpackUint16(msg, off)
	if err != nil {
		return l, off, err
	}
	l.rrtype = RRType(rrtype)

	l.rrsig, off, err = unpackDataSignature(msg, off)
	if err != nil {
		return l, off, err
	}

	return l, off, nil
}

func unpackDataLeavingCNAME(msg []byte, off int) (l LeavingCNAME, off1 int, err error) {
	l = LeavingCNAME{}
	if off == len(msg) {
		return l, off, nil
	}
	l.Leaving, off, err = unpackDataLeaving(msg, off)
	if err != nil {
		return l, off, err
	}
	name, off, err := UnpackDomainName(msg, off)
	if err != nil {
		return l, off, err
	}
	l.name = Name(name)

	return l, off, nil
}

func unpackDataZonePair(msg []byte, off int) (zp ZonePair, off1 int, err error) {
	zp = ZonePair{}
	if off == len(msg) {
		return zp, off, nil
	}

	zp.entry, off, err = unpackDataEntering(msg, off)
	if err != nil {
		return zp, off, err
	}
	zp.exit, off, err = unpackDataLeaving(msg, off)
	if err != nil {
		return zp, off, err
	}

	return zp, off, nil
}
