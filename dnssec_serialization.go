package dns

type ZonePair struct {
	entry Entering
	exit  Leaving
}

type DNSSECProof struct {
	initial_key_tag uint16
	num_zones       uint8
	zones           []ZonePair
}

type ZoneRecType uint8
const (
	EnteringType ZoneRecType = 0
	LeavingType              = 1
)

type Signature struct {
	length    uint16
	algorithm uint8
	labels    uint8
	ttl       uint32
	expires   uint32
	begins    uint32
	key_tag   uint16
	signature string `dns:"base64"`
}

type Key struct {
	length uint16
	rdata  []DNSKEY_Rdata
}

type DNSKEY_Rdata struct {
	flags      uint16
	protocol   uint8
	algorithm  uint8
	public_key string `dns:"base64"`
}

type Entering struct {
	length          uint16
	zType           ZoneRecType
	entry_key_index uint8
	key_sig         Signature
	num_keys        uint8
	keys            []Key
}

type SerialDS struct {
	key_tag     uint16
	algorithm   uint8
	digest_type uint8
	digest_len  uint16
	digest      string `dns:"hex"`
}

type RRType uint16

type Leaving struct {
	length    uint16
	zType     ZoneRecType
	next_name Name
	rrtype    RRType
	rrsig     Signature
}

type LeavingCNAME struct {
	Leaving
	name Name
}

type LeavingDNAME struct {
	LeavingCNAME
}

type LeavingDS struct {
	Leaving
	num_ds     uint8
	ds_records []SerialDS
}

type LeavingOther struct {
	Leaving
	num_rrs uint8
	rrs     []RRData
}

type RRData struct {
	length uint16
	rrdata []byte
}
