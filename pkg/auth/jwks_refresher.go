package auth

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"emperror.dev/errors"
)

// DefaultKeyRefreshInterval is the default period between background JWKS syncs (1 hour).
const DefaultKeyRefreshInterval = 1 * time.Hour

// DefaultKeyRefreshCooldown is the default minimum duration between on-demand JWKS refreshes (10 seconds)
// to prevent endpoint hammering or DoS when unknown key IDs are presented.
const DefaultKeyRefreshCooldown = 10 * time.Second

// KeyRefreshConfig configures background polling and on-demand key synchronization.
type KeyRefreshConfig struct {
	// IAMBaseURL is the base URL for fetching keys over HTTP (e.g. "https://iam.example.com").
	IAMBaseURL string

	// Interval is the period between background polls. Defaults to DefaultKeyRefreshInterval (1h).
	Interval time.Duration

	// Cooldown is the minimum duration between on-demand refresh attempts. Defaults to DefaultKeyRefreshCooldown (10s).
	Cooldown time.Duration

	// FetchOptions holds optional FetchOption customizers (e.g. WithHTTPClient, WithPath, WithMaxBytes).
	FetchOptions []FetchOption

	// Logger is the logger for recording background sync events.
	Logger *slog.Logger
}

// JWKSRefresher manages background synchronization and rate-limited on-demand fetching of JWKS keys.
type JWKSRefresher struct {
	auth      *Authenticator
	cfg       KeyRefreshConfig
	mu        sync.Mutex
	lastFetch time.Time
	stopCh    chan struct{}
	doneCh    chan struct{}
	running   atomic.Bool
	closed    atomic.Bool
}

// NewJWKSRefresher creates and configures a new JWKSRefresher bound to the provided Authenticator.
func NewJWKSRefresher(auth *Authenticator, cfg KeyRefreshConfig) (*JWKSRefresher, error) {
	if auth == nil {
		return nil, errors.New("authenticator must not be nil")
	}
	if cfg.IAMBaseURL == "" {
		return nil, errors.New("IAM base URL is required")
	}
	if cfg.Interval <= 0 {
		cfg.Interval = DefaultKeyRefreshInterval
	}
	if cfg.Cooldown <= 0 {
		cfg.Cooldown = DefaultKeyRefreshCooldown
	}

	r := &JWKSRefresher{
		auth:   auth,
		cfg:    cfg,
		stopCh: make(chan struct{}),
		doneCh: make(chan struct{}),
	}
	auth.SetJWKSRefresher(r)
	return r, nil
}

// FetchNow unconditionally queries IAM for updated verification keys and atomically replaces them
// on the Authenticator.
func (r *JWKSRefresher) FetchNow(ctx context.Context) error {
	if r.closed.Load() {
		return errors.New("jwks refresher is closed")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.fetchNowLocked(ctx)
}

// FetchOnDemand triggers a key refresh if the cooldown duration has elapsed since the last fetch.
// It coalesces concurrent on-demand requests so only one HTTP fetch executes at a time.
// It reports whether a refresh was performed (or freshly completed while waiting for the lock).
func (r *JWKSRefresher) FetchOnDemand(ctx context.Context) (bool, error) {
	if r.closed.Load() {
		return false, errors.New("jwks refresher is closed")
	}

	start := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()

	// If a fetch finished while we were waiting for the lock, keys were freshly updated.
	if !r.lastFetch.IsZero() && r.lastFetch.After(start) {
		return true, nil
	}

	// If last fetch was within Cooldown, throttle to prevent DoS.
	if !r.lastFetch.IsZero() && time.Since(r.lastFetch) < r.cfg.Cooldown {
		return false, nil
	}

	if err := r.fetchNowLocked(ctx); err != nil {
		return false, err
	}
	return true, nil
}

func (r *JWKSRefresher) fetchNowLocked(ctx context.Context) error {
	jwks, err := FetchJWKSHTTP(ctx, r.cfg.IAMBaseURL, r.cfg.FetchOptions...)
	if err != nil {
		if r.cfg.Logger != nil {
			r.cfg.Logger.ErrorContext(ctx, "failed to fetch JWKS keys from IAM",
				slog.Any("error", err),
				slog.String("base_url", r.cfg.IAMBaseURL),
			)
		}
		return err
	}

	keys, err := jwks.VerificationKeys()
	if err != nil {
		if r.cfg.Logger != nil {
			r.cfg.Logger.ErrorContext(ctx, "failed to parse verification keys from JWKS", slog.Any("error", err))
		}
		return err
	}

	if err := r.auth.SetVerificationKeys(keys); err != nil {
		return err
	}

	r.lastFetch = time.Now()
	if r.cfg.Logger != nil {
		r.cfg.Logger.InfoContext(ctx, "successfully refreshed JWKS verification keys",
			slog.String("active_kid", keys.ActiveKeyID()),
			slog.Int("total_keys", len(jwks.Keys)),
		)
	}
	return nil
}

// Start begins the background periodic polling loop.
func (r *JWKSRefresher) Start(ctx context.Context) error {
	if r.closed.Load() {
		return errors.New("jwks refresher is closed")
	}
	if !r.running.CompareAndSwap(false, true) {
		return errors.New("jwks refresher is already running")
	}

	go r.loop(ctx)
	return nil
}

func (r *JWKSRefresher) loop(ctx context.Context) {
	defer close(r.doneCh)
	ticker := time.NewTicker(r.cfg.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-r.stopCh:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			fetchCtx, cancel := context.WithTimeout(ctx, DefaultFetchTimeout)
			_ = r.FetchNow(fetchCtx)
			cancel()
		}
	}
}

// Stop stops the background polling goroutine.
func (r *JWKSRefresher) Stop() {
	if !r.closed.CompareAndSwap(false, true) {
		return
	}
	close(r.stopCh)
	if r.running.Load() {
		<-r.doneCh
	}
}

// Close stops the refresher and releases resources, satisfying io.Closer.
func (r *JWKSRefresher) Close() error {
	r.Stop()
	return nil
}
