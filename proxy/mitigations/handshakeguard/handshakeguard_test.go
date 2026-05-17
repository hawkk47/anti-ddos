package handshakeguard

import (
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

type fakeConn struct {
	net.Conn
	remote     net.Addr
	readQueue  chan []byte
	closed     chan struct{}
	closeOnce  sync.Once
	readErrors error
}

func newFakeConn(remote string) *fakeConn {
	addr, _ := net.ResolveTCPAddr("tcp", remote)
	return &fakeConn{
		remote:    addr,
		readQueue: make(chan []byte, 4),
		closed:    make(chan struct{}),
	}
}

func (f *fakeConn) Read(p []byte) (int, error) {
	select {
	case b := <-f.readQueue:
		n := copy(p, b)
		return n, nil
	case <-f.closed:
		return 0, io.EOF
	}
}
func (f *fakeConn) Close() error                       { f.closeOnce.Do(func() { close(f.closed) }); return nil }
func (f *fakeConn) RemoteAddr() net.Addr               { return f.remote }
func (f *fakeConn) SetReadDeadline(_ time.Time) error  { return nil }
func (f *fakeConn) SetWriteDeadline(_ time.Time) error { return nil }
func (f *fakeConn) SetDeadline(_ time.Time) error      { return nil }
func (f *fakeConn) LocalAddr() net.Addr                { return nil }
func (f *fakeConn) Write(p []byte) (int, error)        { return len(p), nil }

func TestDisabledPasses(t *testing.T) {
	l, _ := New(Config{Enabled: false}, nil)
	if l.Config().Enabled {
		t.Fatal("enabled mismatch")
	}
	// Sanity : wrapping a conn passes through; rien à observer côté Limiter
	// quand Enabled=false car WrapListener.Accept ne pose pas de deadline.
	_ = newFakeConn("8.8.8.8:1234")
}

func TestAbandonReportThreshold(t *testing.T) {
	l, _ := New(Config{
		Enabled:          true,
		HandshakeWindow:  10 * time.Millisecond,
		AbandonThreshold: 3,
		ObserveWindow:    time.Second,
		ReportTTL:        time.Minute,
	}, nil)
	base := time.Unix(1700000000, 0)
	l.now = func() time.Time { return base }
	rp := &fakeReporter{}
	l.SetReporter(rp)
	ip := net.ParseIP("8.8.8.8")
	for i := 0; i < 2; i++ {
		l.recordAbandon(ip)
	}
	if len(rp.calls) != 0 {
		t.Fatalf("no report yet, got %d", len(rp.calls))
	}
	l.recordAbandon(ip)
	if len(rp.calls) != 1 {
		t.Fatalf("expected 1 report at threshold, got %d", len(rp.calls))
	}
}

func TestAbandonWindowExpires(t *testing.T) {
	l, _ := New(Config{
		Enabled:          true,
		HandshakeWindow:  10 * time.Millisecond,
		AbandonThreshold: 2,
		ObserveWindow:    100 * time.Millisecond,
		ReportTTL:        time.Minute,
	}, nil)
	base := time.Unix(1700000000, 0)
	now := base
	l.now = func() time.Time { return now }
	rp := &fakeReporter{}
	l.SetReporter(rp)
	ip := net.ParseIP("8.8.8.8")
	l.recordAbandon(ip)
	now = base.Add(200 * time.Millisecond) // sortie de fenêtre
	l.recordAbandon(ip)
	if len(rp.calls) != 0 {
		t.Fatalf("first stamp expired, should not have reported; got %d", len(rp.calls))
	}
}

func TestLoopbackIgnoredForReport(t *testing.T) {
	l, _ := New(Config{
		Enabled:          true,
		HandshakeWindow:  10 * time.Millisecond,
		AbandonThreshold: 1,
		ObserveWindow:    time.Second,
		ReportTTL:        time.Minute,
	}, nil)
	rp := &fakeReporter{}
	l.SetReporter(rp)
	l.recordAbandon(net.ParseIP("127.0.0.1"))
	if len(rp.calls) != 0 {
		t.Errorf("loopback should never be reported")
	}
}

func TestInvalidConfig(t *testing.T) {
	if _, err := New(Config{Enabled: true, HandshakeWindow: 0}, nil); err == nil {
		t.Error("expected error")
	}
}

type fakeReporter struct {
	calls []net.IP
}

func (f *fakeReporter) BlockIP(ip net.IP, _ time.Duration) {
	f.calls = append(f.calls, ip)
}
