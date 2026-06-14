package web

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// Server is the dashboard HTTP server. It exposes a Start/Name service shape so the
// daemon can run it under a context alongside its other long-lived components.
type Server struct {
	cfg     Config
	data    DataSource
	store   *Store
	auth    *authenticator
	limiter *loginLimiter
	router  http.Handler
	now     func() time.Time // injectable clock for tests
}

// New builds a dashboard server from config, the daemon's data source, and the event
// store. It wires the router eagerly so Handler() is usable immediately (including in
// tests, before Start). A nil store is replaced with an empty 24h store so the UI
// degrades gracefully rather than panicking.
func New(cfg Config, data DataSource, store *Store) *Server {
	cfg = cfg.withDefaults()
	if store == nil {
		store = NewStore(24 * time.Hour)
	}
	auth, err := newAuthenticator(cfg)
	if err != nil {
		// The session signing key could not be generated (OS RNG unavailable). Rather
		// than fall back to a forgeable empty-key HMAC, serve 503 on every route — the
		// dashboard is optional and a broken auth surface must never be reachable.
		return &Server{
			cfg:   cfg,
			data:  data,
			store: store,
			now:   time.Now,
			router: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "dashboard unavailable: could not initialize session security", http.StatusServiceUnavailable)
			}),
		}
	}
	s := &Server{
		cfg:     cfg,
		data:    data,
		store:   store,
		auth:    auth,
		limiter: newLoginLimiter(loginMaxAttempts, loginWindow),
		now:     time.Now,
	}
	s.router = s.buildRouter()
	return s
}

// Handler returns the chi router. It is also used directly in tests via httptest.
func (s *Server) Handler() http.Handler { return s.router }

// Name returns the service name used by the daemon's supervisor.
func (s *Server) Name() string { return "dashboard" }

// secureCookies reports whether session/CSRF cookies should carry the Secure flag.
// On a loopback bind the connection is plain HTTP (TLS terminates at a proxy), so we
// must NOT set Secure or the browser would drop the cookie and break login. Only mark
// cookies Secure when bound to a non-loopback address.
func (s *Server) secureCookies() bool {
	return !isLoopbackListen(s.cfg.Listen)
}

// Start binds cfg.Listen and serves until ctx is cancelled, then shuts down gracefully.
func (s *Server) Start(ctx context.Context) error {
	srv := &http.Server{
		Addr:              s.cfg.Listen,
		Handler:           s.router,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

// buildRouter assembles the chi router: static assets, the login pair, and the
// auth+CSRF-protected application group.
func (s *Server) buildRouter() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.Recoverer)
	r.Use(securityHeaders)

	// Static assets are embedded; they need no auth (and no CSRF). Long cache because
	// asset paths are content-stable within a build.
	r.Handle("/static/*", s.staticHandler())

	r.Get("/login", s.loginForm)
	r.Post("/login", s.loginSubmit)
	r.Post("/logout", s.logout)

	r.Group(func(r chi.Router) {
		r.Use(s.requireAuth)
		r.Use(requireCSRF)

		r.Get("/", s.overview)
		r.Get("/bans", s.bansPage)
		r.Get("/feed", s.feedPage)
		r.Get("/sites", s.sitesPage)
		r.Get("/detectors", s.detectorsPage)

		// HTMX polling partials — HTML fragments, never JSON.
		r.Get("/_p/sentinel", s.pSentinel)
		r.Get("/_p/readouts", s.pReadouts)
		r.Get("/_p/feed", s.pFeed)

		// Write action.
		r.Post("/bans/{ip}/unban", s.unban)
	})

	return r
}

// staticHandler serves embedded assets with a far-future cache header. The CSP and
// nosniff headers come from the global securityHeaders middleware.
func (s *Server) staticHandler() http.Handler {
	fs := http.FileServer(http.FS(staticFS))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		fs.ServeHTTP(w, r)
	})
}
