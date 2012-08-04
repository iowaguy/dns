package main

import (
	"dns"
	"log"
)

func serve(w dns.ResponseWriter, req *dns.Msg, z *dns.Zone) {
	log.Printf("incoming %s %s\n", req.Question[0].Name, dns.Rr_str[req.Question[0].Qtype])
	// Check for referral
	// if we find something with NonAuth = true, it means
	// we need to return referral
	nss := z.Predecessor(req.Question[0].Name)
	if nss != nil && nss.NonAuth {
		log.Printf("Referral")
		m := new(dns.Msg)
		m.SetReply(req)
		m.Ns = nss.RR[dns.TypeNS]
		// lookup the a records for additional, only when
		// in baliwick
		w.Write(m)
		return

	}

	// For now:
	// look up name -> yes, continue, no -> nxdomain
	node := z.Find(req.Question[0].Name)
	if node == nil {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeNameError)
		w.Write(m)
		return
	}
	apex := z.Find(z.Origin)

	// Name found, look for type, yes, answer, no 
	if rrs, ok := node.RR[req.Question[0].Qtype]; ok {
		// Need to look at class to but... no
		m := new(dns.Msg)
		m.SetReply(req)
		m.MsgHdr.Authoritative = true
		m.Answer = rrs
		// auth section
		m.Ns = apex.RR[dns.TypeNS]
		w.Write(m)
		return
	} else {
		// nodate reply
		// soa in auth section
		m := new(dns.Msg)
		m.SetReply(req)
		m.Ns = apex.RR[dns.TypeSOA]
		w.Write(m)
		return
	}
	// See RFC 1035...
	m := new(dns.Msg)
	m.SetRcode(req, dns.RcodeNameError)

	w.Write(m)
}
