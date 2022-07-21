package dns


func (rr *Signature) pack(msg []byte, off int, compression compressionMap, compress bool) (off1 int, err error) {
	return packDataSignature(*rr, msg, off)
}



func packDataSignature(sig Signature, msg []byte, off int) (off1 int, err error) {
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
	off, err = packStringBase64(sig.signature, msg, off)
	if err != nil {
		return off, err
	}

	return off, nil
}
