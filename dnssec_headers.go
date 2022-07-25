package dns

func (rr *ZonePair) Header() *RR_Header     { return nil }
func (rr *DNSSECProof) Header() *RR_Header  { return nil }
func (rr *ZoneRecType) Header() *RR_Header  { return nil }
func (rr *Signature) Header() *RR_Header    { return &RR_Header{} }
func (rr *Key) Header() *RR_Header          { return nil }
func (rr *Entering) Header() *RR_Header     { return nil }
func (rr *SerialDS) Header() *RR_Header     { return nil }
func (rr *RRType) Header() *RR_Header       { return nil }
func (rr *Leaving) Header() *RR_Header      { return nil }
func (rr *LeavingCNAME) Header() *RR_Header { return nil }
func (rr *LeavingDNAME) Header() *RR_Header { return nil }
func (rr *LeavingDS) Header() *RR_Header    { return nil }
func (rr *LeavingOther) Header() *RR_Header { return nil }
func (rr *RRData) Header() *RR_Header       { return nil }
