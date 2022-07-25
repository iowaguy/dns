package dns

import (
	"bytes"
	"strconv"
)

func (rr *ZonePair) String() string {
	return rr.entry.String() + " " + rr.exit.String()
}

func (rr *DNSSECProof) String() string {
	var b bytes.Buffer
	for _, zone := range rr.zones {
		b.WriteString(zone.String())
	}
	return strconv.Itoa(int(rr.initial_key_tag)) + " " +
		strconv.Itoa(int(rr.num_zones)) + " " + b.String()
}

func (rr *ZoneRecType) String() string {
	return strconv.Itoa(int(*rr))
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

func (rr *Key) String() string {
	var b bytes.Buffer
	for _, rdata := range rr.rdata {
		b.WriteString(rdata.String())
	}
	return strconv.Itoa(int(rr.length)) + " " + b.String()
}

func (rr *DNSKEY_Rdata) String() string {
	return strconv.Itoa(int(rr.flags)) + " " +
		strconv.Itoa(int(rr.protocol)) + " " +
		strconv.Itoa(int(rr.algorithm)) + " " +
		sprintName(rr.public_key)
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

func (rr *SerialDS) String() string {
	return strconv.Itoa(int(rr.key_tag)) + " " +
		strconv.Itoa(int(rr.algorithm)) + " " +
		strconv.Itoa(int(rr.digest_type)) + " " +
		strconv.Itoa(int(rr.digest_len)) + " " +
		sprintName(rr.digest)
}

func (rr *RRType) String() string {
	return strconv.Itoa(int(*rr))
}

func (rr *Leaving) String() string {
	return strconv.Itoa(int(rr.length)) + " " +
		rr.zType.String() + " " +
		rr.next_name.String() + " " +
		rr.rrtype.String() + " " +
		rr.rrsig.String()
}

func (rr *LeavingCNAME) String() string {
	return rr.Leaving.String() + " " + rr.name.String()
}

func (rr *LeavingDNAME) String() string {
	return rr.LeavingCNAME.String()
}

func (rr *LeavingDS) String() string {
	var b bytes.Buffer
	for _, ds := range rr.ds_records {
		b.WriteString(ds.String())
	}
	return rr.Leaving.String() + " " +
		strconv.Itoa(int(rr.num_ds)) + " " + b.String()
}

func (rr *LeavingOther) String() string {
	var b bytes.Buffer
	for _, rrdata := range rr.rrs {
		b.WriteString(rrdata.String())
	}
	return strconv.Itoa(int(rr.num_rrs)) + " " + b.String()
}

func (rr *RRData) String() string {
	return strconv.Itoa(int(rr.length)) + " " + string(rr.rrdata)
}
