package dns

func (rr *ZonePair) pack(msg []byte, off int, compression compressionMap, compress bool) (off1 int, err error) {
	return packDataZonePair(rr, msg, off, compression, compress)
}

func (rr *DNSSECProof) pack(msg []byte, off int, compression compressionMap, compress bool) (off1 int, err error) {
	off, err = packUint16(rr.initial_key_tag, msg, off)
	if err != nil {
		return off, err
	}
	off, err = packUint8(rr.num_zones, msg, off)
	if err != nil {
		return off, err
	}

	for _, z := range rr.zones {
		off, err = packDataZonePair(&z, msg, off, compression, compress)
		if err != nil {
			return off, err
		}
	}
	return off, nil
}

func (rr *Signature) pack(msg []byte, off int, compression compressionMap, compress bool) (off1 int, err error) {
	return packDataSignature(rr, msg, off, compression, compress)
}

func (rr *Key) pack(msg []byte, off int, compression compressionMap, compress bool) (off1 int, err error) {
	return packDataKey(rr, msg, off, compression, compress)
}

func (rr *Entering) pack(msg []byte, off int, compression compressionMap, compress bool) (off1 int, err error) {
	return packDataEntering(rr, msg, off, compression, compress)
}

func (rr *SerialDS) pack(msg []byte, off int, compression compressionMap, compress bool) (off1 int, err error) {
	return packDataSerialDS(rr, msg, off, compression, compress)
}

func (rr *Leaving) pack(msg []byte, off int, compression compressionMap, compress bool) (off1 int, err error) {
	return packDataLeaving(rr, msg, off, compression, compress)
}

func (rr *LeavingCNAME) pack(msg []byte, off int, compression compressionMap, compress bool) (off1 int, err error) {
	return packDataLeavingCNAME(rr, msg, off, compression, compress)
}

func (rr *LeavingDNAME) pack(msg []byte, off int, compression compressionMap, compress bool) (off1 int, err error) {
	return packDataLeavingCNAME(&rr.LeavingCNAME, msg, off, compression, compress)
}

func (rr *LeavingDS) pack(msg []byte, off int, compression compressionMap, compress bool) (off1 int, err error) {
	off, err = packDataLeaving(&rr.Leaving, msg, off, compression, compress)
	if err != nil {
		return off, err
	}
	off, err = packUint8(rr.num_ds, msg, off)
	if err != nil {
		return off, err
	}
	for _, ds := range rr.ds_records {
		off, err = packDataSerialDS(&ds, msg, off, compression, compress)
		if err != nil {
			return off, err
		}
	}

	return off, nil
}

func (rr *LeavingOther) pack(msg []byte, off int, compression compressionMap, compress bool) (off1 int, err error) {
	off, err = packDataLeaving(&rr.Leaving, msg, off, compression, compress)
	if err != nil {
		return off, err
	}
	off, err = packUint8(rr.num_rrs, msg, off)
	if err != nil {
		return off, err
	}
	for _, r := range rr.rrs {
		off, err = packDataRRData(&r, msg, off, compression, compress)
		if err != nil {
			return off, err
		}
	}

	return off, nil
}

func (rr *RRData) pack(msg []byte, off int, compression compressionMap, compress bool) (off1 int, err error) {
	return packDataRRData(rr, msg, off, compression, compress)
}

func packDataRRData(rrd *RRData, msg []byte, off int, compression compressionMap, compress bool) (off1 int, err error) {
	off, err = packUint16(rrd.length, msg, off)
	if err != nil {
		return off, err
	}
	off, err = packByteArray(rrd.rrdata, msg, off, compression, compress)
	if err != nil {
		return off, err
	}

	return off, nil
}

func packDataSignature(sig *Signature, msg []byte, off int, compression compressionMap, compress bool) (off1 int, err error) {
	off, err = packUint16(sig.length, msg, off)
	if err != nil {
		return off, err
	}
	off, err = packUint8(sig.algorithm, msg, off)
	if err != nil {
		return off, err
	}
	off, err = packUint8(sig.labels, msg, off)
	if err != nil {
		return off, err
	}
	off, err = packUint32(sig.ttl, msg, off)
	if err != nil {
		return off, err
	}
	off, err = packUint32(sig.expires, msg, off)
	if err != nil {
		return off, err
	}
	off, err = packUint32(sig.begins, msg, off)
	if err != nil {
		return off, err
	}
	off, err = packUint16(sig.key_tag, msg, off)
	if err != nil {
		return off, err
	}
	off, err = packByteArray(sig.signature, msg, off, compression, compress)
	if err != nil {
		return off, err
	}

	return off, nil
}

func packDataZonePair(zp *ZonePair, msg []byte, off int, compression compressionMap, compress bool) (off1 int, err error) {
	off, err = packDataEntering(&zp.entry, msg, off, compression, compress)
	if err != nil {
		return off, err
	}

	off, err = packDataLeaving(&zp.exit, msg, off, compression, compress)
	if err != nil {
		return off, err
	}

	return off, nil
}

func packDataKey(key *Key, msg []byte, off int, compression compressionMap, compress bool) (off1 int, err error) {
	off, err = packUint16(key.length, msg, off)
	if err != nil {
		return off, err
	}
	off, err = packUint16(key.flags, msg, off)
	if err != nil {
		return off, err
	}
	off, err = packUint8(key.protocol, msg, off)
	if err != nil {
		return off, err
	}
	off, err = packUint8(key.algorithm, msg, off)
	if err != nil {
		return off, err
	}
	off, err = packByteArray(key.public_key, msg, off, compression, compress)
	if err != nil {
		return off, err
	}

	return off, nil
}

func packByteArray(b []byte, msg []byte, off int, compression compressionMap, compress bool) (off1 int, err error) {
	copy(msg[off:], b)
	return off + len(b), nil
}

func packDataEntering(entry *Entering, msg []byte, off int, compression compressionMap, compress bool) (off1 int, err error) {
	off, err = packUint16(entry.length, msg, off)
	if err != nil {
		return off, err
	}
	off, err = packUint8(uint8(entry.zType), msg, off)
	if err != nil {
		return off, err
	}
	off, err = packUint8(entry.entry_key_index, msg, off)
	if err != nil {
		return off, err
	}
	off, err = packDataSignature(&entry.key_sig, msg, off, compression, compress)
	if err != nil {
		return off, err
	}
	off, err = packUint8(entry.num_keys, msg, off)
	if err != nil {
		return off, err
	}
	for _, k := range entry.keys {
		off, err = packDataKey(&k, msg, off, compression, compress)
		if err != nil {
			return off, err
		}
	}

	return off, nil
}

func packDataSerialDS(ds *SerialDS, msg []byte, off int, compression compressionMap, compress bool) (off1 int, err error) {
	off, err = packUint16(ds.length, msg, off)
	if err != nil {
		return off, err
	}
	off, err = packUint16(ds.key_tag, msg, off)
	if err != nil {
		return off, err
	}
	off, err = packUint8(ds.algorithm, msg, off)
	if err != nil {
		return off, err
	}
	off, err = packUint8(ds.digest_type, msg, off)
	if err != nil {
		return off, err
	}
	off, err = packUint16(ds.digest_len, msg, off)
	if err != nil {
		return off, err
	}
	off, err = packByteArray(ds.digest, msg, off, compression, compress)
	if err != nil {
		return off, err
	}

	return off, nil
}

func packDataLeaving(l *Leaving, msg []byte, off int, compression compressionMap, compress bool) (off1 int, err error) {
	off, err = packUint16(l.length, msg, off)
	if err != nil {
		return off, err
	}
	off, err = packUint8(uint8(l.zType), msg, off)
	if err != nil {
		return off, err
	}
	off, err = packDomainName(string(l.next_name), msg, off, compression, compress)
	if err != nil {
		return off, err
	}
	off, err = packUint16(uint16(l.rrtype), msg, off)
	if err != nil {
		return off, err
	}
	off, err = packDataSignature(&l.rrsig, msg, off, compression, compress)
	if err != nil {
		return off, err
	}

	return off, nil
}

func packDataLeavingCNAME(l *LeavingCNAME, msg []byte, off int, compression compressionMap, compress bool) (off1 int, err error) {
	off, err = packDataLeaving(&l.Leaving, msg, off, compression, compress)
	if err != nil {
		return off, err
	}
	off, err = packDomainName(string(l.name), msg, off, compression, compress)
	if err != nil {
		return off, err
	}

	return off, nil
}
