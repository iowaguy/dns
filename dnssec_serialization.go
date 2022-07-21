package dns

import (
	"bytes"
	"strconv"
)

type ZonePair struct {
	entry Entering
	exit  Leaving
}

func (rr *ZonePair) String() string {
	return rr.entry.String() + " " + rr.exit.String()
}

type DNSSECProof struct {
	initial_key_tag uint16
	num_zones       uint8
	zones           []ZonePair
}

func (rr *DNSSECProof) String() string {
	var b bytes.Buffer
	for _, zone := range rr.zones {
		b.WriteString(zone.String())
	}
	return strconv.Itoa(int(rr.initial_key_tag)) + " " +
		strconv.Itoa(int(rr.num_zones)) + " " + b.String()
}

type ZoneRecType uint8

const (
	EnteringType ZoneRecType = 0
	LeavingType              = 1
)

func (rr *ZoneRecType) String() string {
	return strconv.Itoa(int(*rr))
}

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

func (rr *Signature) String() string {
	return strconv.Itoa(int(rr.length)) + " " +
		strconv.Itoa(int(rr.algorithm)) + " " +
		strconv.Itoa(int(rr.labels)) + " " +
		strconv.Itoa(int(rr.ttl)) + " " +
		strconv.Itoa(int(rr.expires)) + " " +
		strconv.Itoa(int(rr.begins)) + " " +
		strconv.Itoa(int(rr.key_tag)) + " " +
		sprintName(rr.signature)
}

type Key struct {
	length uint16
	rdata  []DNSKEY_Rdata
}

func (rr *Key) String() string {
	var b bytes.Buffer
	for _, rdata := range rr.rdata {
		b.WriteString(rdata.String())
	}
	return strconv.Itoa(int(rr.length)) + " " + b.String()
}

type DNSKEY_Rdata struct {
	flags      uint16
	protocol   uint8
	algorithm  uint8
	public_key string `dns:"base64"`
}

func (rr *DNSKEY_Rdata) String() string {
	return strconv.Itoa(int(rr.flags)) + " " +
		strconv.Itoa(int(rr.protocol)) + " " +
		strconv.Itoa(int(rr.algorithm)) + " " +
		sprintName(rr.public_key)
}

type Entering struct {
	length          uint16
	zType           ZoneRecType
	entry_key_index uint8
	key_sig         Signature
	num_keys        uint8
	keys            []Key
}

func (rr *Entering) String() string {
	var b bytes.Buffer
	for _, key := range rr.keys {
		b.WriteString(key.String())
	}
	return strconv.Itoa(int(rr.length)) + " " +
		rr.zType.String() + " " +
		strconv.Itoa(int(rr.entry_key_index)) + " " +
		rr.key_sig.String() + " " +
		strconv.Itoa(int(rr.num_keys)) + " " +
		b.String()
}

type SerialDS struct {
	key_tag     uint16
	algorithm   uint8
	digest_type uint8
	digest_len  uint16
	digest      string `dns:"hex"`
}

func (rr *SerialDS) String() string {
	return strconv.Itoa(int(rr.key_tag)) + " " +
		strconv.Itoa(int(rr.algorithm)) + " " +
		strconv.Itoa(int(rr.digest_type)) + " " +
		strconv.Itoa(int(rr.digest_len)) + " " +
		sprintName(rr.digest)
}

type RRType uint16

func (rr *RRType) String() string {
	return strconv.Itoa(int(*rr))
}

type Leaving struct {
	length    uint16
	zType     ZoneRecType
	next_name Name
	rrtype    RRType
	rrsig     Signature
}

func (rr *Leaving) String() string {
	return strconv.Itoa(int(rr.length)) + " " +
		rr.zType.String() + " " +
		rr.next_name.String() + " " +
		rr.rrtype.String() + " " +
		rr.rrsig.String()
}

type LeavingCNAME struct {
	Leaving
	name Name
}

func (rr *LeavingCNAME) String() string {
	return rr.Leaving.String() + " " + rr.name.String()
}

type LeavingDNAME struct {
	LeavingCNAME
}

func (rr *LeavingDNAME) String() string {
	return rr.LeavingCNAME.String()
}

type LeavingDS struct {
	Leaving
	num_ds     uint8
	ds_records []SerialDS
}

func (rr *LeavingDS) String() string {
	var b bytes.Buffer
	for _, ds := range rr.ds_records {
		b.WriteString(ds.String())
	}
	return rr.Leaving.String() + " " +
		strconv.Itoa(int(rr.num_ds)) + " " + b.String()
}

type LeavingOther struct {
	num_rrs uint8
	rrs     []RRData
}

func (rr *LeavingOther) String() string {
	var b bytes.Buffer
	for _, rrdata := range rr.rrs {
		b.WriteString(rrdata.String())
	}
	return strconv.Itoa(int(rr.num_rrs)) + " " + b.String()
}

type RRData struct {
	length uint16
	rrdata []byte
}

func (rr *RRData) String() string {
	return strconv.Itoa(int(rr.length)) + " " + string(rr.rrdata)
}
