package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
	"time"

	"tailscale.com/ipn/ipnlocal"
)

// TLS certificates for serveHTTPS.
//
// Tailscale's ACME code (feature/acme) issues the node's certificate, keeps
// it in the state store and decides when it is due for renewal. certManager
// holds the parsed certificate in memory for TLS handshakes and asks
// Tailscale for it again once an hour. That hourly call is what lets
// Tailscale renew: its own refresh loop only runs for hosts in a serve
// config, which this build omits.

const (
	certRefreshInterval = time.Hour
	certLoadTimeout     = 3 * time.Minute
	certNotRunningPoll  = time.Second

	// After a failed load the next one waits certRetryMin, doubling per
	// consecutive failure up to certRetryMax. TLS handshakes do not start
	// a load before then, so a broken setup cannot burn through Let's
	// Encrypt's rate limits.
	certRetryMin = time.Minute
	certRetryMax = time.Hour

	// certRenewNow is a validity no certificate has, so Tailscale renews.
	certRenewNow = time.Duration(1<<63 - 1)
)

var (
	errNotRunning    = errors.New("node is not connected to the tailnet")
	errHTTPSDisabled = errors.New("HTTPS certificates are not enabled for this tailnet; turn them on in the Tailscale admin console under DNS > HTTPS Certificates")
	errHTTPSClosed   = errors.New("HTTPS listener closed")
)

type certManager struct {
	logf func(format string, args ...any)
	now  func() time.Time

	// domain returns the name to get a certificate for. It fails with
	// errNotRunning until the node has a netmap, and with
	// errHTTPSDisabled if the tailnet has no certificate domains.
	domain func() (string, error)

	// getCertPEM is LocalBackend.GetCertPEMWithValidity.
	getCertPEM func(ctx context.Context, domain string, minValidity time.Duration) (*ipnlocal.TLSCertKeyPair, error)

	mu         sync.Mutex
	cert       *tls.Certificate // nil until the first successful load
	certDomain string
	err        error         // why the last load failed; nil after a success
	failures   int           // consecutive failed loads
	retryAt    time.Time     // no new load before this time
	loading    *certLoad     // non-nil while a load is in flight
	first      chan struct{} // closed after the first load with an outcome
	firstDone  bool
	users      int // HTTPS listeners using this manager
	stop       context.CancelFunc
	poke       chan struct{} // wakes run when the node's state changes
}

// certLoad is one call into Tailscale, shared by everyone who wants the
// certificate while it runs.
type certLoad struct {
	done chan struct{}
	cert *tls.Certificate
	err  error
}

func newCertManager(
	logf func(format string, args ...any),
	domain func() (string, error),
	getCertPEM func(context.Context, string, time.Duration) (*ipnlocal.TLSCertKeyPair, error),
) *certManager {
	return &certManager{
		logf:       logf,
		now:        time.Now,
		domain:     domain,
		getCertPEM: getCertPEM,
		first:      make(chan struct{}),
		poke:       make(chan struct{}, 1),
	}
}

// acquire registers an HTTPS listener and starts the refresh loop for the
// first one. Every acquire needs a release.
func (m *certManager) acquire() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.users++
	if m.users == 1 {
		ctx, cancel := context.WithCancel(context.Background())
		m.stop = cancel
		go m.run(ctx)
	}
}

func (m *certManager) release() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.users--
	if m.users == 0 {
		m.stop()
		m.stop = nil
	}
}

// stateChanged tells the refresh loop that the node's state changed, so it
// does not have to wait for its next poll to see that the node is running.
func (m *certManager) stateChanged() {
	select {
	case m.poke <- struct{}{}:
	default:
	}
}

// run loads the certificate as soon as the node is running, then keeps it
// fresh until ctx is done.
func (m *certManager) run(ctx context.Context) {
	for {
		wait, running := m.refresh(ctx)
		var poke <-chan struct{}
		if !running {
			poke = m.poke
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-poke:
			t.Stop()
		case <-t.C:
		}
	}
}

// refresh is one iteration of run. It returns how long to wait before the
// next one, and whether the node was running.
func (m *certManager) refresh(ctx context.Context) (wait time.Duration, running bool) {
	m.mu.Lock()
	retryIn := m.retryAt.Sub(m.now())
	m.mu.Unlock()
	if retryIn > 0 {
		return retryIn, true
	}
	_, err := m.load(ctx, 0)
	switch {
	case err == nil:
		return certRefreshInterval, true
	case errors.Is(err, errNotRunning):
		return certNotRunningPoll, false
	case errors.Is(err, errHTTPSDisabled):
		// Cheap to check again, and fixed in the admin console
		// without touching this node.
		return certRetryMin, true
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return max(m.retryAt.Sub(m.now()), certRetryMin), true
}

// getCertificate is the tls.Config.GetCertificate of HTTPS listeners. Any
// server name gets the node's certificate: a client that used another name
// then reports the mismatch itself, which says more than a failed handshake.
func (m *certManager) getCertificate(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return m.certificate(hi.Context())
}

// certificate returns the certificate for a handshake that ctx belongs to:
// the one in memory while it is valid, otherwise whatever a load gives.
func (m *certManager) certificate(ctx context.Context) (*tls.Certificate, error) {
	m.mu.Lock()
	cert, err, retryAt := m.cert, m.err, m.retryAt
	m.mu.Unlock()
	now := m.now()
	if cert != nil && now.Before(cert.Leaf.NotAfter) {
		return cert, nil
	}
	if err != nil && now.Before(retryAt) {
		return nil, fmt.Errorf("no TLS certificate, next attempt at %s: %w", retryAt.UTC().Format(time.RFC3339), err)
	}
	return m.load(ctx, 0)
}

// load asks Tailscale for the certificate, which comes from the state store
// or is issued, and makes it the current one. Calls that overlap share one
// request. ctx only bounds the wait: the request itself keeps going, so a
// client that gives up on its handshake does not abort an issuance.
func (m *certManager) load(ctx context.Context, minValidity time.Duration) (*tls.Certificate, error) {
	m.mu.Lock()
	l := m.loading
	if l == nil {
		l = m.startLoadLocked(minValidity)
	}
	m.mu.Unlock()
	select {
	case <-l.done:
		return l.cert, l.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// renew replaces the certificate with a newly issued one.
func (m *certManager) renew(ctx context.Context) (*tls.Certificate, error) {
	for {
		m.mu.Lock()
		l := m.loading
		if l == nil {
			l = m.startLoadLocked(certRenewNow)
			m.mu.Unlock()
			select {
			case <-l.done:
				return l.cert, l.err
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		m.mu.Unlock()
		// An ordinary load is in flight and would hand back the
		// current certificate. Let it finish first.
		select {
		case <-l.done:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func (m *certManager) startLoadLocked(minValidity time.Duration) *certLoad {
	l := &certLoad{done: make(chan struct{})}
	m.loading = l
	go func() {
		cert, domain, cached, err := m.fetch(minValidity)
		m.finishLoad(cert, domain, cached, err)
		l.cert, l.err = cert, err
		close(l.done)
	}()
	return l
}

func (m *certManager) fetch(minValidity time.Duration) (cert *tls.Certificate, domain string, cached bool, err error) {
	domain, err = m.domain()
	if err != nil {
		return nil, "", false, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), certLoadTimeout)
	defer cancel()
	pair, err := m.getCertPEM(ctx, domain, minValidity)
	if err != nil {
		return nil, domain, false, fmt.Errorf("getting a certificate for %s: %w", domain, err)
	}
	c, err := tls.X509KeyPair(pair.CertPEM, pair.KeyPEM)
	if err != nil {
		return nil, domain, false, fmt.Errorf("certificate for %s: %w", domain, err)
	}
	if c.Leaf == nil {
		if c.Leaf, err = x509.ParseCertificate(c.Certificate[0]); err != nil {
			return nil, domain, false, fmt.Errorf("certificate for %s: %w", domain, err)
		}
	}
	return &c, domain, pair.Cached, nil
}

// finishLoad records the outcome of a load and logs what changed.
func (m *certManager) finishLoad(cert *tls.Certificate, domain string, cached bool, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.loading = nil
	if errors.Is(err, errNotRunning) {
		return // not an outcome yet; run tries again shortly
	}
	if !m.firstDone {
		m.firstDone = true
		close(m.first)
	}
	if err != nil {
		if m.err == nil || m.err.Error() != err.Error() {
			m.logf("https: %v", err)
		}
		m.err = err
		if !errors.Is(err, errHTTPSDisabled) {
			m.failures++
			m.retryAt = m.now().Add(min(certRetryMin<<min(m.failures-1, 10), certRetryMax))
		}
		return
	}
	prev := m.cert
	m.cert, m.certDomain, m.err, m.failures, m.retryAt = cert, domain, nil, 0, time.Time{}
	if prev != nil && bytes.Equal(prev.Certificate[0], cert.Certificate[0]) {
		return
	}
	what := "issued a new certificate"
	switch {
	case cached && prev == nil:
		what = "using the stored certificate"
	case cached:
		what = "using the renewed certificate"
	}
	m.logf("https: %s for %s, expires %s", what, domain, cert.Leaf.NotAfter.UTC().Format(time.RFC3339))
}

// waitFirst blocks until the first load has an outcome and returns it.
func (m *certManager) waitFirst(ctx context.Context) (*certInfo, error) {
	select {
	case <-m.first:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	info, err := m.info()
	if info == nil && err == nil {
		err = errors.New("no TLS certificate")
	}
	if info != nil {
		err = nil // serving; a later refresh failure is in status()
	}
	return info, err
}

// certInfo describes the certificate in use.
type certInfo struct {
	Domain string
	Expiry time.Time
}

func (c *certInfo) js() map[string]any {
	return map[string]any{"domain": c.Domain, "expiry": c.Expiry.UTC().Format(time.RFC3339)}
}

// info returns the certificate in use, if any, and the error of the last
// load, if it failed.
func (m *certManager) info() (*certInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cert == nil {
		return nil, m.err
	}
	return &certInfo{Domain: m.certDomain, Expiry: m.cert.Leaf.NotAfter}, m.err
}
