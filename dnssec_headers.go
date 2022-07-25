package dns

func (rr *ZonePair) Header() *RR_Header     { return &RR_Header{} }
func (rr *DNSSECProof) Header() *RR_Header  { return &RR_Header{} }
func (rr *ZoneRecType) Header() *RR_Header  { return &RR_Header{} }
func (rr *Signature) Header() *RR_Header    { return &RR_Header{} }
func (rr *Key) Header() *RR_Header          { return &RR_Header{} }
func (rr *Entering) Header() *RR_Header     { return &RR_Header{} }
func (rr *SerialDS) Header() *RR_Header     { return &RR_Header{} }
func (rr *RRType) Header() *RR_Header       { return &RR_Header{} }
func (rr *Leaving) Header() *RR_Header      { return &RR_Header{} }
func (rr *LeavingCNAME) Header() *RR_Header { return &RR_Header{} }
func (rr *LeavingDNAME) Header() *RR_Header { return &RR_Header{} }
func (rr *LeavingDS) Header() *RR_Header    { return &RR_Header{} }
func (rr *LeavingOther) Header() *RR_Header { return &RR_Header{} }
func (rr *RRData) Header() *RR_Header       { return &RR_Header{} }
func (rr *DNSKEY_Rdata) Header() *RR_Header { return &RR_Header{} }
