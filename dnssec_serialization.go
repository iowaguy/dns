package dns

type ZonePair struct {
	Entry Entering
	Exit  Leaving
}

type DNSSECProof struct {
	Initial_key_tag uint16
	Num_zones       uint8
	Zones           []ZonePair
}

type ZoneRecType uint8

const (
	EnteringType ZoneRecType = 0
	LeavingType              = 1
)

type Signature struct {
	Length    uint16
	Algorithm uint8
	Labels    uint8
	Ttl       uint32
	Expires   uint32
	Begins    uint32
	Key_tag   uint16
	Signature []byte
}

type Key struct {
	Length     uint16
	Flags      uint16
	Protocol   uint8
	Algorithm  uint8
	Public_key []byte
}

type Entering struct {
	Length          uint16
	ZType           ZoneRecType
	Entry_key_index uint8
	Key_sig         Signature
	Num_keys        uint8
	Keys            []Key
}

type SerialDS struct {
	Length      uint16
	Key_tag     uint16
	Algorithm   uint8
	Digest_type uint8
	Digest_len  uint16
	Digest      []byte
}

type RRType uint16

type Leaving struct {
	Length    uint16
	ZType     ZoneRecType
	Next_name Name
	Rrtype    RRType
	Rrsig     Signature
}

type LeavingCNAME struct {
	Leaving
	Name Name
}

type LeavingDNAME struct {
	LeavingCNAME
}

type LeavingDS struct {
	Leaving
	Num_ds     uint8
	Ds_records []SerialDS
}

type LeavingOther struct {
	Leaving
	Num_rrs uint8
	Rrs     []RRData
}

type RRData struct {
	Length uint16
	Rrdata []byte
}
