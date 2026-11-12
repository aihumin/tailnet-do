package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"syscall/js"
	"testing"
	"time"

	"tailscale.com/ipn/ipnlocal"
)

const testDomain = "node.example.ts.net"

// testCA issues certificates for tests.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{cert: cert, key: key}
}

var testSerial int64 = 1

// issue returns a certificate for testDomain valid from notBefore to
// notAfter, as Tailscale would return it.
func (ca *testCA) issue(t *testing.T, notBefore, notAfter time.Time, cached bool) *ipnlocal.TLSCertKeyPair {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	testSerial++
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(testSerial),
		Subject:      pkix.Name{CommonName: testDomain},
		DNSNames:     []string{testDomain},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return &ipnlocal.TLSCertKeyPair{
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		KeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
		Cached:  cached,
	}
}

// fakeTailscale stands in for the LocalBackend behind a certManager.
type fakeTailscale struct {
	mu          sync.Mutex
	now         time.Time
	domainErr   error
	pair        *ipnlocal.TLSCertKeyPair
	err         error
	calls       int
	validities  []time.Duration
	block       chan struct{} // if non-nil, getCertPEM waits for it
	logs        []string
	certManager *certManager
}

func newFakeTailscale(t *testing.T) *fakeTailscale {
	f := &fakeTailscale{now: time.Now()}
	f.certManager = newCertManager(
		func(format string, args ...any) {
			line := fmt.Sprintf(format, args...)
			t.Log(line)
			f.mu.Lock()
			f.logs = append(f.logs, line)
			f.mu.Unlock()
		},
		func() (string, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			return testDomain, f.domainErr
		},
		func(ctx context.Context, domain string, minValidity time.Duration) (*ipnlocal.TLSCertKeyPair, error) {
			f.mu.Lock()
			f.calls++
			f.validities = append(f.validities, minValidity)
			block, pair, err := f.block, f.pair, f.err
			f.mu.Unlock()
			if domain != testDomain {
				return nil, fmt.Errorf("asked for %q, want %q", domain, testDomain)
			}
			if block != nil {
				<-block
			}
			return pair, err
		},
	)
	f.certManager.now = func() time.Time {
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.now
	}
	return f
}

func (f *fakeTailscale) set(fn func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn()
}

func (f *fakeTailscale) numCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *fakeTailscale) logged(substr string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, l := range f.logs {
		if strings.Contains(l, substr) {
			return true
		}
	}
	return false
}

// handlerForTest returns what netstack would call for a connection to port.
func (n *node) handlerForTest(port uint16) (func(net.Conn), bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	l, ok := n.listeners[port]
	if !ok {
		return nil, false
	}
	return func(c net.Conn) { l.handle(c, netip.AddrPort{}) }, true
}

func samePair(c *tls.Certificate, p *ipnlocal.TLSCertKeyPair) bool {
	block, _ := pem.Decode(p.CertPEM)
	return c != nil && bytes.Equal(c.Certificate[0], block.Bytes)
}

func TestCertManagerServesFromMemory(t *testing.T) {
	ca := newTestCA(t)
	f := newFakeTailscale(t)
	m := f.certManager
	stored := ca.issue(t, f.now.Add(-time.Hour), f.now.Add(90*24*time.Hour), true)
	f.set(func() { f.pair = stored })

	for i := range 3 {
		cert, err := m.certificate(context.Background())
		if err != nil {
			t.Fatalf("handshake %d: %v", i, err)
		}
		if !samePair(cert, stored) {
			t.Fatalf("handshake %d: got a different certificate", i)
		}
	}
	if n := f.numCalls(); n != 1 {
		t.Errorf("Tailscale was asked for the certificate %d times, want 1", n)
	}
	if !f.logged("using the stored certificate for " + testDomain) {
		t.Error("no log line says the stored certificate was used")
	}
	info, err := m.info()
	if err != nil || info == nil || info.Domain != testDomain || !info.Expiry.Equal(m.cert.Leaf.NotAfter) {
		t.Errorf("info = %+v, %v", info, err)
	}
}

func TestCertManagerLogsIssuance(t *testing.T) {
	ca := newTestCA(t)
	f := newFakeTailscale(t)
	f.set(func() { f.pair = ca.issue(t, f.now.Add(-time.Hour), f.now.Add(90*24*time.Hour), false) })
	if _, err := f.certManager.load(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	if !f.logged("issued a new certificate for " + testDomain) {
		t.Error("no log line says a certificate was issued")
	}
}

func TestCertManagerHTTPSDisabled(t *testing.T) {
	f := newFakeTailscale(t)
	m := f.certManager
	f.set(func() { f.domainErr = errHTTPSDisabled })

	_, err := m.certificate(context.Background())
	if !errors.Is(err, errHTTPSDisabled) {
		t.Fatalf("handshake error = %v, want errHTTPSDisabled", err)
	}
	if _, err := m.waitFirst(context.Background()); !errors.Is(err, errHTTPSDisabled) {
		t.Errorf("waitFirst = %v, want errHTTPSDisabled", err)
	}
	if n := f.numCalls(); n != 0 {
		t.Errorf("Tailscale was asked for a certificate %d times with HTTPS disabled", n)
	}
	if wait, _ := m.refresh(context.Background()); wait != certRetryMin {
		t.Errorf("refresh wait = %v, want %v", wait, certRetryMin)
	}

	// Enabled in the admin console: the next handshake gets a certificate.
	ca := newTestCA(t)
	f.set(func() {
		f.domainErr = nil
		f.pair = ca.issue(t, f.now.Add(-time.Hour), f.now.Add(time.Hour), false)
	})
	if _, err := m.certificate(context.Background()); err != nil {
		t.Fatalf("handshake after enabling HTTPS: %v", err)
	}
	if _, err := m.info(); err != nil {
		t.Errorf("error still reported after a successful load: %v", err)
	}
}

func TestCertManagerNotRunningIsNotAnOutcome(t *testing.T) {
	f := newFakeTailscale(t)
	m := f.certManager
	f.set(func() { f.domainErr = errNotRunning })

	wait, running := m.refresh(context.Background())
	if running || wait != certNotRunningPoll {
		t.Errorf("refresh = %v, %v; want %v, false", wait, running, certNotRunningPoll)
	}
	select {
	case <-m.first:
		t.Error("first outcome reported while the node is not running")
	default:
	}
	if _, err := m.info(); err != nil {
		t.Errorf("info error = %v, want none", err)
	}
}

func TestCertManagerBacksOffAfterFailure(t *testing.T) {
	f := newFakeTailscale(t)
	m := f.certManager
	f.set(func() { f.err = errors.New("acme: rate limited") })

	if _, err := m.certificate(context.Background()); err == nil {
		t.Fatal("handshake succeeded without a certificate")
	}
	// More handshakes and refreshes inside the backoff must not reach
	// Tailscale (and through it, Let's Encrypt).
	for range 5 {
		_, err := m.certificate(context.Background())
		if err == nil || !strings.Contains(err.Error(), "rate limited") {
			t.Fatalf("handshake in backoff: err = %v, want the load error", err)
		}
	}
	if wait, _ := m.refresh(context.Background()); wait != certRetryMin {
		t.Errorf("refresh wait in backoff = %v, want %v", wait, certRetryMin)
	}
	if n := f.numCalls(); n != 1 {
		t.Fatalf("Tailscale was asked %d times, want 1", n)
	}

	// Each failure doubles the wait, up to certRetryMax.
	want := certRetryMin
	for i := 2; i < 12; i++ {
		f.set(func() { f.now = f.now.Add(want) })
		want = min(want*2, certRetryMax)
		if wait, _ := m.refresh(context.Background()); wait != want {
			t.Fatalf("wait after failure %d = %v, want %v", i, wait, want)
		}
		if n := f.numCalls(); n != i {
			t.Fatalf("Tailscale was asked %d times after %d backoffs, want %d", n, i-1, i)
		}
	}

	// Success clears the backoff.
	ca := newTestCA(t)
	f.set(func() {
		f.now = f.now.Add(certRetryMax)
		f.err = nil
		f.pair = ca.issue(t, f.now.Add(-time.Hour), f.now.Add(time.Hour), false)
	})
	if wait, _ := m.refresh(context.Background()); wait != certRefreshInterval {
		t.Errorf("wait after success = %v, want %v", wait, certRefreshInterval)
	}
	if _, err := m.certificate(context.Background()); err != nil {
		t.Errorf("handshake after recovery: %v", err)
	}
}

func TestCertManagerPicksUpRenewal(t *testing.T) {
	ca := newTestCA(t)
	f := newFakeTailscale(t)
	m := f.certManager
	old := ca.issue(t, f.now.Add(-60*24*time.Hour), f.now.Add(30*24*time.Hour), true)
	f.set(func() { f.pair = old })
	if wait, _ := m.refresh(context.Background()); wait != certRefreshInterval {
		t.Fatalf("refresh wait = %v, want %v", wait, certRefreshInterval)
	}

	// Tailscale renewed in the background; the hourly refresh sees it.
	renewed := ca.issue(t, f.now, f.now.Add(90*24*time.Hour), true)
	f.set(func() { f.pair = renewed })
	if cert, _ := m.certificate(context.Background()); !samePair(cert, old) {
		t.Fatal("handshake before the refresh did not use the certificate in memory")
	}
	m.refresh(context.Background())
	if cert, _ := m.certificate(context.Background()); !samePair(cert, renewed) {
		t.Fatal("handshake after the refresh did not use the renewed certificate")
	}
	if !f.logged("using the renewed certificate") {
		t.Error("no log line says the renewed certificate was picked up")
	}
}

func TestCertManagerReloadsExpiredCert(t *testing.T) {
	ca := newTestCA(t)
	f := newFakeTailscale(t)
	m := f.certManager
	f.set(func() { f.pair = ca.issue(t, f.now.Add(-time.Hour), f.now.Add(time.Hour), true) })
	if _, err := m.certificate(context.Background()); err != nil {
		t.Fatal(err)
	}

	fresh := ca.issue(t, f.now, f.now.Add(48*time.Hour), false)
	f.set(func() {
		f.now = f.now.Add(2 * time.Hour)
		f.pair = fresh
	})
	cert, err := m.certificate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !samePair(cert, fresh) {
		t.Error("handshake used the expired certificate")
	}
}

func TestCertManagerSharesOneLoad(t *testing.T) {
	ca := newTestCA(t)
	f := newFakeTailscale(t)
	m := f.certManager
	block := make(chan struct{})
	f.set(func() {
		f.block = block
		f.pair = ca.issue(t, f.now.Add(-time.Hour), f.now.Add(time.Hour), false)
	})

	const handshakes = 8
	errs := make(chan error, handshakes)
	for range handshakes {
		go func() {
			_, err := m.certificate(context.Background())
			errs <- err
		}()
	}
	// A waiter that gives up must not cancel the load for the others.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := m.load(ctx, 0); !errors.Is(err, context.Canceled) {
		t.Errorf("load with a canceled context = %v", err)
	}
	close(block)
	for range handshakes {
		if err := <-errs; err != nil {
			t.Error(err)
		}
	}
	if n := f.numCalls(); n != 1 {
		t.Errorf("Tailscale was asked %d times for %d concurrent handshakes, want 1", n, handshakes)
	}
}

func TestCertManagerRenew(t *testing.T) {
	ca := newTestCA(t)
	f := newFakeTailscale(t)
	m := f.certManager
	f.set(func() { f.pair = ca.issue(t, f.now.Add(-time.Hour), f.now.Add(time.Hour), true) })
	if _, err := m.load(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	renewed := ca.issue(t, f.now, f.now.Add(48*time.Hour), false)
	f.set(func() { f.pair = renewed })
	cert, err := m.renew(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !samePair(cert, renewed) {
		t.Error("renew did not return the new certificate")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if got := f.validities[len(f.validities)-1]; got != certRenewNow {
		t.Errorf("renew asked Tailscale for validity %v, want %v", got, certRenewNow)
	}
}

func TestCertManagerRunStopsOnRelease(t *testing.T) {
	ca := newTestCA(t)
	f := newFakeTailscale(t)
	m := f.certManager
	f.set(func() { f.pair = ca.issue(t, f.now.Add(-time.Hour), f.now.Add(time.Hour), true) })
	m.acquire()
	if _, err := m.waitFirst(context.Background()); err != nil {
		t.Fatalf("run did not load the certificate: %v", err)
	}
	m.release()
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stop != nil {
		t.Error("refresh loop still has a cancel func after the last release")
	}
}

// TestServeHTTPS runs a request through the same listener, TLS config and
// handler adapter that serveHTTPS sets up, with a JS handler on the other
// side, and checks the certificate the client sees.
func TestServeHTTPS(t *testing.T) {
	ca := newTestCA(t)
	f := newFakeTailscale(t)
	f.set(func() { f.pair = ca.issue(t, f.now.Add(-time.Hour), f.now.Add(time.Hour), true) })

	handler := js.FuncOf(func(_ js.Value, a []js.Value) any {
		req := a[0]
		res := js.Global().Get("Object").New()
		res.Set("status", 200)
		res.Set("headers", js.ValueOf([]any{[]any{"content-type", "text/plain"}}))
		res.Set("body", toJSBytes([]byte(req.Get("method").String()+" "+req.Get("url").String())))
		return js.Global().Get("Promise").Call("resolve", res)
	})
	defer handler.Release()

	n := &node{listeners: map[uint16]portListener{}, certs: f.certManager}
	ready := n.serveHTTPS(443, handler.Value)
	defer n.setListener(443, nil, nil)
	if info, err := ready(); err != nil || info.Domain != testDomain {
		t.Fatalf("ready = %+v, %v", info, err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)
	for _, proto := range []string{"http/1.1", "h2"} {
		t.Run(proto, func(t *testing.T) {
			client := &http.Client{Transport: &http.Transport{
				ForceAttemptHTTP2: proto == "h2",
				TLSClientConfig:   &tls.Config{RootCAs: roots, NextProtos: []string{proto}},
				DialContext: func(context.Context, string, string) (net.Conn, error) {
					c, s := net.Pipe()
					handle, ok := n.handlerForTest(443)
					if !ok {
						return nil, errors.New("nothing listens on 443")
					}
					go handle(s)
					return c, nil
				},
			}}
			defer client.CloseIdleConnections()
			resp, err := client.Get("https://" + testDomain + "/hello?x=1")
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			if want := "GET https://" + testDomain + "/hello?x=1"; string(body) != want {
				t.Errorf("body = %q, want %q", body, want)
			}
			if resp.TLS == nil || resp.TLS.NegotiatedProtocol != proto {
				t.Errorf("negotiated protocol = %+v, want %s", resp.TLS, proto)
			}
			if got := resp.Header.Get("content-type"); got != "text/plain" {
				t.Errorf("content-type = %q", got)
			}
		})
	}

	// Closing the listener stops the refresh loop it started.
	n.setListener(443, nil, nil)
	if f.certManager.users != 0 {
		t.Errorf("certManager has %d users after the listener closed", f.certManager.users)
	}
}

func TestServeHTTPSReadyFailsWhenClosed(t *testing.T) {
	f := newFakeTailscale(t)
	f.set(func() { f.domainErr = errNotRunning })
	n := &node{listeners: map[uint16]portListener{}, certs: f.certManager}
	ready := n.serveHTTPS(443, js.Undefined())
	n.setListener(443, nil, nil)
	if _, err := ready(); !errors.Is(err, errHTTPSClosed) {
		t.Errorf("ready after close = %v, want errHTTPSClosed", err)
	}
}
