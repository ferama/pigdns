package recursor

import (
	"errors"

	"github.com/miekg/dns"
)

var (
	errNSECTypeExists      = errors.New("NSEC3 record shows question type exists")
	errNSECMissingCoverage = errors.New("NSEC3 record missing for expected encloser")
	errNSECBadDelegation   = errors.New("DS or SOA bit set in NSEC3 type map")
	errNSECNSMissing       = errors.New("NS bit not set in NSEC3 type map")
	errNSECOptOut          = errors.New("Opt-Out bit not set for NSEC3 record covering next closer")
)

func nsecTypesSet(set []uint16, types ...uint16) bool {
	tm := make(map[uint16]bool, len(types))
	for _, t := range types {
		tm[t] = true
	}
	for _, t := range set {
		if _, ok := tm[t]; ok {
			return true
		}
	}
	return false
}

func nsecGetDnameTarget(msg *dns.Msg) string {
	var target string

	q := msg.Question[0]

	for _, r := range msg.Answer {
		if dname, ok := r.(*dns.DNAME); ok {
			if n := dns.CompareDomainName(dname.Header().Name, q.Name); n > 0 {
				labels := dns.CountLabel(q.Name)

				if n == labels {
					target = dname.Target
				} else {
					prev, _ := dns.PrevLabel(q.Name, n)
					target = q.Name[:prev] + dname.Target
				}
			}

			return target
		}
	}

	return target
}

func nsecVerifyNODATA(msg *dns.Msg, nsec []dns.RR) error {
	q := msg.Question[0]
	qname := q.Name

	if dname := nsecGetDnameTarget(msg); dname != "" {
		qname = dname
	}
	types, err := nsecFindMatching(qname, nsec)
	if err != nil {
		if q.Qtype != dns.TypeDS {
			return err
		}
		ce, nc := nsecFindClosestEncloser(qname, nsec)
		if ce == "" {
			return errNSECMissingCoverage
		}
		_, _, err := nsecFindCoverer(nc, nsec)
		if err != nil {
			return err
		}
		return nil
	}

	if nsecTypesSet(types, q.Qtype, dns.TypeCNAME) {
		return errNSECTypeExists
	}

	return nil
}

func nsecFindMatching(name string, nsec []dns.RR) ([]uint16, error) {
	for _, rr := range nsec {
		n := rr.(*dns.NSEC3)
		if n.Match(name) {
			return n.TypeBitMap, nil
		}
	}
	return nil, errNSECMissingCoverage
}

func nsecFindClosestEncloser(name string, nsec []dns.RR) (string, string) {
	labelIndices := dns.Split(name)
	nc := name
	for i := 0; i < len(labelIndices); i++ {
		z := name[labelIndices[i]:]
		_, err := nsecFindMatching(z, nsec)
		if err != nil {
			continue
		}
		if i != 0 {
			nc = name[labelIndices[i-1]:]
		}
		return z, nc
	}
	return "", ""
}

func nsecFindCoverer(name string, nsec []dns.RR) ([]uint16, bool, error) {
	for _, rr := range nsec {
		n := rr.(*dns.NSEC3)
		if n.Cover(name) {
			return n.TypeBitMap, (n.Flags & 1) == 1, nil
		}
	}
	return nil, false, errNSECMissingCoverage
}

func nsecVerifyDelegation(delegation string, nsec []dns.RR) error {
	types, err := nsecFindMatching(delegation, nsec)
	if err != nil {
		ce, nc := nsecFindClosestEncloser(delegation, nsec)
		if ce == "" {
			return errNSECMissingCoverage
		}
		_, optOut, err := nsecFindCoverer(nc, nsec)
		if err != nil {
			return err
		}
		if !optOut {
			return errNSECOptOut
		}
		return nil
	}
	if !nsecTypesSet(types, dns.TypeNS) {
		return errNSECNSMissing
	}
	if nsecTypesSet(types, dns.TypeDS, dns.TypeSOA) {
		return errNSECBadDelegation
	}
	return nil
}
