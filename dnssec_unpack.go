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


func unpackDataSignature(msg []byte, off int) (sig Signature, off1 int, err error) {
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
	sig.signature, off, err = unpackStringBase64(msg, off, -1)
	if err != nil {
		return sig, off, err
	}

	return sig, off, nil
}
