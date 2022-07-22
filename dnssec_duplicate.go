package dns

func (rr *ZonePair) isDuplicate(_r2 RR) bool {
	return false
}

func (rr *DNSSECProof) isDuplicate(_r2 RR) bool {
	return false
}

func (rr *Signature) isDuplicate(_r2 RR) bool {
	return false
}

func (rr *Key) isDuplicate(_r2 RR) bool {
	return false
}

func (rr *DNSKEY_Rdata) isDuplicate(_r2 RR) bool {
	return false
}

func (rr *Entering) isDuplicate(_r2 RR) bool {
	return false
}

func (rr *SerialDS) isDuplicate(_r2 RR) bool {
	return false
}

func (rr *Leaving) isDuplicate(_r2 RR) bool {
	return false
}

func (rr *LeavingCNAME) isDuplicate(_r2 RR) bool {
	return false
}

func (rr *LeavingDNAME) isDuplicate(_r2 RR) bool {
	return false
}

func (rr *LeavingDS) isDuplicate(_r2 RR) bool {
	return false
}

func (rr *LeavingOther) isDuplicate(_r2 RR) bool {
	return false
}

func (rr *RRData) isDuplicate(_r2 RR) bool {
	return false
}
