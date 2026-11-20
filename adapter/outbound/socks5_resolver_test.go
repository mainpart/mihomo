package outbound

import (
	"context"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/component/trie"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/socks5"

	D "github.com/miekg/dns"
)

// These tests temporarily change process-wide DNS globals; the resolver can
// finish background queries after cancellation, so the process owns them.
func isolateDNSGlobals(t *testing.T) bool {
	t.Helper()
	if os.Getenv("MIHOMO_TEST_SOCKS_DNS") == t.Name() {
		return false
	}
	cmd := exec.Command(os.Args[0], "-test.run=^"+regexp.QuoteMeta(t.Name())+"$")
	cmd.Env = append(os.Environ(), "MIHOMO_TEST_SOCKS_DNS="+t.Name())
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("isolated test: %v\n%s", err, out)
	}
	return true
}

// dnsSocks is a single synthetic corporate SOCKS and DNS, never an external tunnel.
type dnsSocks struct {
	listener net.Listener
	udp      *net.UDPConn
	mu       sync.Mutex
	queries  []string
	mode     map[string]string
}

func newDNSSocks(t *testing.T) *dnsSocks {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tcpAddr := ln.Addr().(*net.TCPAddr)
	u, err := net.ListenUDP("udp4", &net.UDPAddr{IP: tcpAddr.IP, Port: tcpAddr.Port})
	if err != nil {
		ln.Close()
		t.Fatal(err)
	}
	s := &dnsSocks{listener: ln, udp: u, mode: map[string]string{"127.0.0.10": "drop", "127.0.0.11": "answer"}}
	t.Cleanup(func() { ln.Close(); u.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, cmd, _, err := socks5.ServerHandshake(c, nil)
				if err != nil {
					return
				}
				if cmd == socks5.CmdConnect {
					_, _ = c.Write([]byte("OK"))
					return
				}
				_, _ = io.Copy(io.Discard, c)
			}()
		}
	}()
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := u.ReadFromUDP(buf)
			if err != nil {
				return
			}
			packet := append([]byte(nil), buf[:n]...)
			addr, payload, err := socks5.DecodeUDPPacket(packet)
			if err != nil {
				continue
			}
			dst := addr.UDPAddr()
			if dst == nil {
				continue
			}
			if dst.Port != 53 {
				wire, err := socks5.EncodeUDPPacket(addr, append([]byte("echo:"), payload...))
				if err == nil {
					_, _ = u.WriteToUDP(wire, from)
				}
				continue
			}
			var q D.Msg
			if q.Unpack(payload) != nil || len(q.Question) == 0 {
				continue
			}
			s.mu.Lock()
			mode := s.mode[dst.IP.String()]
			s.queries = append(s.queries, dst.IP.String()+":"+q.Question[0].Name)
			s.mu.Unlock()
			if mode == "drop" {
				continue
			}
			go func() {
				if mode == "slow" {
					time.Sleep(200 * time.Millisecond)
				}
				var answer D.Msg
				answer.SetReply(&q)
				if mode == "nxdomain" {
					answer.Rcode = D.RcodeNameError
				} else {
					last := byte(17)
					if mode == "answer2" {
						last = 18
					}
					answer.Answer = []D.RR{&D.A{Hdr: D.RR_Header{Name: q.Question[0].Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 60}, A: net.IPv4(10, 22, 0, last)}}
				}
				b, err := answer.Pack()
				if err != nil {
					return
				}
				wire, err := socks5.EncodeUDPPacket(addr, b)
				if err == nil {
					_, _ = u.WriteToUDP(wire, from)
				}
			}()
		}
	}()
	return s
}

func (s *dnsSocks) setModes(m map[string]string) { s.mu.Lock(); s.mode = m; s.mu.Unlock() }
func (s *dnsSocks) count() int                   { s.mu.Lock(); defer s.mu.Unlock(); return len(s.queries) }

func TestSocksResolverDNSValidation(t *testing.T) {
	for _, test := range []struct {
		name    string
		udp     bool
		servers []string
		wantErr bool
	}{
		{"legacy", false, nil, false},
		{"empty", true, []string{}, true},
		{"valid", true, []string{"10.0.0.1", "10.0.0.2"}, false},
		{"udp required", false, []string{"10.0.0.1"}, true},
		{"domain", true, []string{"dns.example"}, true},
		{"port", true, []string{"10.0.0.1:53"}, true},
		{"proxy suffix", true, []string{"10.0.0.1#corp"}, true},
		{"unspecified", true, []string{"0.0.0.0"}, true},
		{"multicast", true, []string{"ff02::1"}, true},
		{"mapped multicast", true, []string{"::ffff:224.0.0.1"}, true},
		{"mapped zone", true, []string{"::ffff:10.0.0.1%en0"}, true},
		{"broadcast", true, []string{"255.255.255.255"}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ss, err := NewSocks5(Socks5Option{Name: "test", Server: "127.0.0.1", Port: 1080, UDP: test.udp, ResolverDNS: test.servers})
			if (err != nil) != test.wantErr {
				t.Fatalf("NewSocks5 error = %v", err)
			}
			if err == nil && (ss.localResolver != nil) != (len(test.servers) > 0) {
				t.Fatal("unexpected resolver")
			}
		})
	}
}

func TestSocksResolverDNSViaOwnSOCKS(t *testing.T) {
	if isolateDNSGlobals(t) {
		return
	}
	s := newDNSSocks(t)
	resolver.DisableIPv6 = true
	hosts := trie.New[resolver.HostValue]()
	if err := hosts.Insert("same.test", resolver.HostValue{IPs: []netip.Addr{netip.MustParseAddr("192.0.2.9")}}); err != nil {
		t.Fatal(err)
	}
	if err := hosts.Insert("outage.test", resolver.HostValue{IPs: []netip.Addr{netip.MustParseAddr("192.0.2.10")}}); err != nil {
		t.Fatal(err)
	}
	resolver.DefaultHosts = resolver.NewHosts(hosts)
	port := s.listener.Addr().(*net.TCPAddr).Port
	corp, err := NewSocks5(Socks5Option{Name: "corp", Server: "127.0.0.1", Port: port, UDP: true, ResolverDNS: []string{"127.0.0.10", "127.0.0.11"}})
	if err != nil {
		t.Fatal(err)
	}
	ordinary, err := NewSocks5(Socks5Option{Name: "ordinary", Server: "127.0.0.1", Port: port, UDP: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		outbound *Socks5
		want     string
	}{{corp, "10.22.0.17"}, {ordinary, "192.0.2.9"}, {corp, "10.22.0.17"}, {ordinary, "192.0.2.9"}} {
		m := &C.Metadata{Host: "same.test", DstIP: netip.MustParseAddr("192.0.2.8"), DstPort: 1234}
		if err := tc.outbound.ResolveUDP(context.Background(), m); err != nil {
			t.Fatal(err)
		}
		// An already-resolved ordinary IP retains legacy behavior; a fresh one uses global hosts.
		if tc.outbound == ordinary {
			m.DstIP = netip.Addr{}
			if err := ordinary.ResolveUDP(context.Background(), m); err != nil {
				t.Fatal(err)
			}
		}
		if m.DstIP.String() != tc.want {
			t.Fatalf("%s resolved %s, want %s", tc.outbound.Name(), m.DstIP, tc.want)
		}
	}
	if s.count() < 2 {
		t.Fatal("expected DNS over SOCKS to both configured servers")
	}
	udpMetadata := &C.Metadata{NetWork: C.UDP, Host: "same.test", DstPort: 1234}
	pc, err := corp.ListenPacketContext(context.Background(), udpMetadata)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	if _, err := pc.WriteTo([]byte("probe"), udpMetadata.UDPAddr()); err != nil {
		t.Fatal(err)
	}
	if err := pc.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 32)
	n, _, err := pc.ReadFrom(reply)
	if err != nil || string(reply[:n]) != "echo:probe" {
		t.Fatalf("UDP SOCKS failed: %q, %v", reply[:n], err)
	}
	s.setModes(map[string]string{"127.0.0.10": "drop", "127.0.0.11": "answer2"})
	beforeFlush := &C.Metadata{Host: "same.test"}
	if err := corp.ResolveUDP(context.Background(), beforeFlush); err != nil || beforeFlush.DstIP.String() != "10.22.0.17" {
		t.Fatalf("cached answer: %v %v", beforeFlush.DstIP, err)
	}
	corp.ClearDNSCache()
	afterFlush := &C.Metadata{Host: "same.test"}
	if err := corp.ResolveUDP(context.Background(), afterFlush); err != nil || afterFlush.DstIP.String() != "10.22.0.18" {
		t.Fatalf("flushed answer: %v %v", afterFlush.DstIP, err)
	}
	m := &C.Metadata{Host: "same.test", DstPort: 18080}
	c, err := corp.DialContext(context.Background(), m)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	b := make([]byte, 2)
	if _, err := io.ReadFull(c, b); err != nil || string(b) != "OK" {
		t.Fatalf("TCP SOCKS failed: %q, %v", b, err)
	}
	// An outage for a new name cannot fall back to global hosts or the public resolver.
	s.setModes(map[string]string{"127.0.0.10": "drop", "127.0.0.11": "drop"})
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if err := corp.ResolveUDP(ctx, &C.Metadata{Host: "outage.test"}); err == nil {
		t.Fatal("DNS outage unexpectedly resolved")
	}
}

func TestSocksResolverDNSFirstNXDOMAINWins(t *testing.T) {
	if isolateDNSGlobals(t) {
		return
	}
	s := newDNSSocks(t)
	s.setModes(map[string]string{"127.0.0.10": "nxdomain", "127.0.0.11": "slow"})
	resolver.DisableIPv6 = true
	corp, err := NewSocks5(Socks5Option{Name: "corp", Server: "127.0.0.1", Port: s.listener.Addr().(*net.TCPAddr).Port, UDP: true, ResolverDNS: []string{"127.0.0.10", "127.0.0.11"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := corp.ResolveUDP(context.Background(), &C.Metadata{Host: "nx.test"}); err == nil {
		t.Fatal("first NXDOMAIN unexpectedly fell back")
	}
}

type wrongFamilyResolver struct {
	resolver.Resolver
	ip netip.Addr
}

func (r wrongFamilyResolver) LookupIPv4(context.Context, string) ([]netip.Addr, error) {
	return []netip.Addr{r.ip}, nil
}
func (r wrongFamilyResolver) LookupIPv6(context.Context, string) ([]netip.Addr, error) {
	return []netip.Addr{r.ip}, nil
}

func TestSocksResolverDNSWrongFamily(t *testing.T) {
	if isolateDNSGlobals(t) {
		return
	}
	resolver.DisableIPv6 = false
	for _, tc := range []struct {
		prefer C.DNSPrefer
		ip     string
	}{{C.IPv6Only, "192.0.2.1"}, {C.IPv4Only, "2001:db8::1"}} {
		ss, err := NewSocks5(Socks5Option{Name: "test", Server: "127.0.0.1", Port: 1080})
		if err != nil {
			t.Fatal(err)
		}
		ss.prefer = tc.prefer
		ss.localResolver = wrongFamilyResolver{ip: netip.MustParseAddr(tc.ip)}
		if err := ss.ResolveUDP(context.Background(), &C.Metadata{Host: "family.test"}); err == nil {
			t.Fatalf("wrong family %s was accepted", tc.ip)
		}
	}
}
