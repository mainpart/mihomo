package statistic

import (
	"net"
	"net/netip"
	"sync"
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

type testConn struct{ C.Conn }

func (testConn) RemoteDestination() string   { return "" }
func (testConn) Chains() C.Chain             { return nil }
func (testConn) ProviderChains() C.Chain     { return nil }
func (testConn) Read(p []byte) (int, error)  { return copy(p, "reply"), nil }
func (testConn) Write(p []byte) (int, error) { return len(p), nil }
func (testConn) Close() error                { return nil }

type testPacketConn struct{ C.PacketConn }

func (testPacketConn) RemoteDestination() string                 { return "" }
func (testPacketConn) Chains() C.Chain                           { return nil }
func (testPacketConn) ProviderChains() C.Chain                   { return nil }
func (testPacketConn) ReadFrom(p []byte) (int, net.Addr, error)  { return copy(p, "udp"), nil, nil }
func (testPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) { return len(p), nil }
func (testPacketConn) Close() error                              { return nil }

func TestUserTrafficIncludesClosedTCPAndUDP(t *testing.T) {
	m := &Manager{epoch: "test"}
	meta := &C.Metadata{InUser: "alice"}
	tcp := NewTCPTracker(testConn{}, m, meta, nil, 2, 1, true)
	_, _ = tcp.Write([]byte("hello"))
	_, _ = tcp.Read(make([]byte, 8))
	_ = tcp.Close()
	udp := NewUDPTracker(testPacketConn{}, m, meta, nil, 0, 0, true)
	_, _ = udp.WriteTo([]byte("ping"), nil)
	_, _, _ = udp.ReadFrom(make([]byte, 8))
	_ = udp.Close()
	ignored := NewTCPTracker(testConn{}, m, &C.Metadata{InUser: "bob"}, nil, 0, 0, false)
	_, _ = ignored.Write([]byte("ignored"))
	_ = ignored.Close()
	epoch, users := m.UserTrafficSnapshot()
	if epoch != "test" || len(users) != 1 || users["alice"] != (UserTraffic{Upload: 11, Download: 9}) {
		t.Fatalf("unexpected counters: %q %#v", epoch, users)
	}
	if len(m.Snapshot().Connections) != 0 {
		t.Fatal("closed connections remain active")
	}
}

func TestUserTrafficConcurrent(t *testing.T) {
	m := &Manager{}
	const workers = 16
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tracker := NewTCPTracker(testConn{}, m, &C.Metadata{InUser: "alice"}, nil, 0, 0, true)
			_, _ = tracker.Write([]byte("hello"))
			_ = tracker.Close()
		}()
	}
	wg.Wait()
	_, users := m.UserTrafficSnapshot()
	if users["alice"].Upload != workers*5 {
		t.Fatalf("lost concurrent updates: %#v", users)
	}
}

func TestUserTrafficSeparatesUsersBehindNAT(t *testing.T) {
	m := &Manager{}
	sharedIP := netip.MustParseAddr("192.0.2.1")
	for user, size := range map[string]int{"alice": 3, "bob": 7} {
		tracker := NewTCPTracker(testConn{}, m, &C.Metadata{InUser: user, SrcIP: sharedIP}, nil, 0, 0, true)
		_, _ = tracker.Write(make([]byte, size))
		_ = tracker.Close()
	}
	_, users := m.UserTrafficSnapshot()
	if users["alice"].Upload != 3 || users["bob"].Upload != 7 || len(users) != 2 {
		t.Fatalf("users with a shared address were not separated: %#v", users)
	}
}
