package pigdns

import (
	"errors"
	"net"
	"strings"

	"github.com/miekg/dns"
)

const (
	FamilyIPv4 = 1
	FamilyIPv6 = 2
)

type Request struct {
	Msg            *dns.Msg
	ResponseWriter dns.ResponseWriter

	name   string // lowercase qname.
	family int8   // transport's family.
	ip     string // client's ip.
}

func (r *Request) NewWithQuestion(name string, typ uint16) *Request {
	req1 := Request{ResponseWriter: r.ResponseWriter, Msg: r.Msg.Copy()}
	req1.Msg.Question[0] = dns.Question{Name: dns.Fqdn(name), Qclass: dns.ClassINET, Qtype: typ}
	return &req1
}

// Reply to the request
func (r *Request) Reply(m *dns.Msg) {
	m.SetReply(r.Msg)
	r.ResponseWriter.WriteMsg(m)
}

func (r *Request) ReplyWithStatus(m *dns.Msg, rcode int) {
	m.SetReply(r.Msg)
	m.SetRcode(r.Msg, rcode)
	r.ResponseWriter.WriteMsg(m)
}

// IP gets the (remote) IP address of the client making the request.
func (r *Request) IP() string {
	if r.ip != "" {
		return r.ip
	}

	ip, _, err := net.SplitHostPort(r.ResponseWriter.RemoteAddr().String())
	if err != nil {
		r.ip = r.ResponseWriter.RemoteAddr().String()
		return r.ip
	}

	r.ip = ip
	return r.ip
}

// Proto gets the protocol used as the transport. This will be udp or tcp.
func (r *Request) Proto() string {
	if _, ok := r.ResponseWriter.RemoteAddr().(*net.UDPAddr); ok {
		return "udp"
	}
	if _, ok := r.ResponseWriter.RemoteAddr().(*net.TCPAddr); ok {
		return "tcp"
	}
	return "udp"
}

// Family returns the family of the transport, 1 for IPv4 and 2 for IPv6.
func (r *Request) Family() int {
	if r.family != 0 {
		return int(r.family)
	}

	var a net.IP
	ip := r.ResponseWriter.RemoteAddr()
	if i, ok := ip.(*net.UDPAddr); ok {
		a = i.IP
	}
	if i, ok := ip.(*net.TCPAddr); ok {
		a = i.IP
	}

	if a.To4() != nil {
		r.family = FamilyIPv4
		return FamilyIPv4
	}
	r.family = FamilyIPv6
	return FamilyIPv6
}

func (r *Request) FamilyIsIPv6() bool {
	return r.Family() == FamilyIPv6
}

func (r *Request) FamilyIsIPv4() bool {
	return r.Family() == FamilyIPv4
}

// Name returns the name of the question in the request. Note
// this name will always have a closing dot and will be lower cased. After a call Name
// the value will be cached. To clear this caching call Clear.
// If the request is malformed the root zone is returned.
func (r *Request) Name() string {
	if r.name != "" {
		return r.name
	}
	if r.Msg == nil {
		r.name = "."
		return "."
	}
	if len(r.Msg.Question) == 0 {
		r.name = "."
		return "."
	}

	r.name = strings.ToLower(dns.Name(r.Msg.Question[0].Name).String())
	return r.name
}

func (r *Request) Question() (dns.Question, error) {
	if r.Msg == nil {
		return dns.Question{}, errors.New("no question available")
	}
	if len(r.Msg.Question) == 0 {
		return dns.Question{}, errors.New("no question available")
	}
	return r.Msg.Question[0], nil
}

// QName returns the name of the question in the request.
// If the request is malformed the root zone is returned.
func (r *Request) QName() string {
	if r.Msg == nil {
		return "."
	}
	if len(r.Msg.Question) == 0 {
		return "."
	}

	return dns.Name(r.Msg.Question[0].Name).String()
}

// Type returns the type of the question as a string. If the request is malformed the empty string is returned.
func (r *Request) Type() string {
	if r.Msg == nil {
		return ""
	}
	if len(r.Msg.Question) == 0 {
		return ""
	}

	return dns.Type(r.Msg.Question[0].Qtype).String()
}

// QType returns the type of the question as an uint16. If the request is malformed
// 0 is returned.
func (r *Request) QType() uint16 {
	if r.Msg == nil {
		return 0
	}
	if len(r.Msg.Question) == 0 {
		return 0
	}

	return r.Msg.Question[0].Qtype
}

// Class returns the class of the question in the request.
// If the request is malformed the empty string is returned.
func (r *Request) Class() string {
	if r.Msg == nil {
		return ""
	}
	if len(r.Msg.Question) == 0 {
		return ""
	}

	return dns.Class(r.Msg.Question[0].Qclass).String()
}

// QClass returns the class of the question in the request.
// If the request is malformed 0 returned.
func (r *Request) QClass() uint16 {
	if r.Msg == nil {
		return 0
	}
	if len(r.Msg.Question) == 0 {
		return 0
	}

	return r.Msg.Question[0].Qclass
}
