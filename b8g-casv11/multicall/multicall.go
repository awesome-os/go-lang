// Package multicall implements the Awesome-OS Multicall Go Runtime Dispatcher.
//
// Instead of spawning separate Go binaries (each carrying its own ~4 MB Go
// runtime and isolated cache state), multicall hosts gitaly, gitlab-shell,
// gitlab-pages, gitlab-runner, workhorse, and b8g-gocacheprog inside ONE
// shared Go runtime process backed by a single casv11.Store and a single
// B8G_ARENA_V1 host-pipe IPC bus address (rule B8G016).
package multicall

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"

	casv11 "github.com/awesome-os/go-lang/b8g-casv11"
)

const (
	// WindowsBusAddress is the canonical Windows named-pipe host bus address.
	WindowsBusAddress = `\\.\pipe\b8g-host-bus`

	// UnixBusAddress is the canonical Linux/macOS Unix domain socket host bus address.
	UnixBusAddress = "/run/b8g/host-bus.sock"
)

var (
	// ErrEmptyBusAddress is returned when a bus address is empty or whitespace-only.
	ErrEmptyBusAddress = errors.New("multicall: empty host bus address")

	// ErrLoopbackHTTPForbidden is returned when a bus address violates B8G016
	// by using loopback HTTP/HTTPS or localhost/127.0.0.1 endpoints.
	ErrLoopbackHTTPForbidden = errors.New("multicall: B8G016 forbids loopback/HTTP IPC")

	// ErrUnknownApplet is returned when no applet is registered under the resolved name.
	ErrUnknownApplet = errors.New("multicall: unknown applet")

	// ErrNilStore is returned when Dispatch is called without a shared casv11.Store.
	ErrNilStore = errors.New("multicall: shared casv11.Store is required")
)

// DefaultApplets lists the canonical Go service applets hosted inside the
// unified multicall Go runtime.
var DefaultApplets = []string{
	"b8g-gocacheprog",
	"gitaly",
	"gitlab-pages",
	"gitlab-runner",
	"gitlab-shell",
	"workhorse",
}

// AppletFunc is the entrypoint signature for a multicall Go applet executing
// within the shared Go runtime, shared casv11.Store, and validated B8G bus.
type AppletFunc func(ctx context.Context, args []string, store *casv11.Store, busAddr string) error

// AppletDescriptor is the canonical metadata payload stored in the shared
// casv11.Store when a built-in multicall applet initializes on the host bus.
type AppletDescriptor struct {
	Applet   string   `json:"applet"`
	BusAddr  string   `json:"busAddr"`
	ABIMagic uint32   `json:"abiMagic"`
	Args     []string `json:"args,omitempty"`
}

// DefaultBusAddress returns the canonical B8G host-pipe IPC bus address for goos:
// `\\.\pipe\b8g-host-bus` on Windows and `/run/b8g/host-bus.sock` on Linux/macOS.
// When goos is empty, runtime.GOOS is used.
func DefaultBusAddress(goos string) string {
	if strings.TrimSpace(goos) == "" {
		goos = runtime.GOOS
	}
	if strings.EqualFold(goos, "windows") {
		return WindowsBusAddress
	}
	return UnixBusAddress
}

// ValidateBusAddress enforces workspace rule B8G016 by strictly rejecting
// empty addresses, loopback hosts (127.0.0.1, localhost, ::1), and HTTP/HTTPS
// transport schemes (http://, https://).
func ValidateBusAddress(addr string) error {
	trimmed := strings.TrimSpace(addr)
	if trimmed == "" {
		return ErrEmptyBusAddress
	}

	lower := strings.ToLower(trimmed)
	forbiddenTokens := []string{
		"http://",
		"https://",
		"127.0.0.1",
		"localhost",
		"[::1]",
		"::1",
	}
	for _, tok := range forbiddenTokens {
		if strings.Contains(lower, tok) {
			return fmt.Errorf("%w: rejected %q (matched %q)", ErrLoopbackHTTPForbidden, addr, tok)
		}
	}
	return nil
}

// ResolveAppletName extracts the normalized applet name from an argv[0] value
// just like BusyBox/toybox, handling both POSIX ('/') and Windows ('\') path
// separators and stripping any trailing ".exe" extension.
func ResolveAppletName(argv0 string) string {
	s := strings.TrimSpace(argv0)
	if s == "" {
		return ""
	}
	if idx := strings.LastIndexAny(s, `/\`); idx >= 0 {
		s = s[idx+1:]
	}
	s = strings.ToLower(s)
	s = strings.TrimSuffix(s, ".exe")
	return s
}

// Registry maps normalized applet names to their in-process AppletFunc
// implementations so all applets share one Go runtime, one casv11.Store,
// and one validated B8G_ARENA_V1 host bus address.
type Registry struct {
	mu      sync.RWMutex
	applets map[string]AppletFunc
}

// NewEmptyRegistry creates a Registry with no applets registered.
func NewEmptyRegistry() *Registry {
	return &Registry{
		applets: make(map[string]AppletFunc),
	}
}

// NewRegistry creates a Registry pre-populated with all default Awesome-OS
// multicall applets: b8g-gocacheprog, gitaly, gitlab-shell, gitlab-pages,
// gitlab-runner, and workhorse.
func NewRegistry() *Registry {
	r := NewEmptyRegistry()
	r.Register("b8g-gocacheprog", builtinGocacheProgApplet)
	for _, name := range []string{
		"gitaly",
		"gitlab-shell",
		"gitlab-pages",
		"gitlab-runner",
		"workhorse",
	} {
		r.Register(name, newBuiltinServiceApplet(name))
	}
	return r
}

// Register binds applet (normalized via ResolveAppletName) to fn.
// Empty names or nil functions are ignored.
func (r *Registry) Register(applet string, fn AppletFunc) {
	name := ResolveAppletName(applet)
	if name == "" || fn == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.applets == nil {
		r.applets = make(map[string]AppletFunc)
	}
	r.applets[name] = fn
}

// Has reports whether an applet matching argv0 is registered.
func (r *Registry) Has(applet string) bool {
	name := ResolveAppletName(applet)
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.applets[name]
	return ok
}

// Applets returns a sorted list of all registered applet names.
func (r *Registry) Applets() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.applets))
	for k := range r.applets {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

// Dispatch resolves applet (supporting BusyBox-style argv[0] paths such as
// "gitaly.exe" or "/usr/bin/gitlab-pages"), validates busAddr against B8G016,
// and executes the registered AppletFunc against the shared casv11.Store.
// If busAddr is empty, DefaultBusAddress(runtime.GOOS) is used.
func (r *Registry) Dispatch(
	ctx context.Context,
	applet string,
	args []string,
	store *casv11.Store,
	busAddr string,
) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if store == nil {
		return ErrNilStore
	}
	if strings.TrimSpace(busAddr) == "" {
		busAddr = DefaultBusAddress(runtime.GOOS)
	}
	if err := ValidateBusAddress(busAddr); err != nil {
		return err
	}

	name := ResolveAppletName(applet)
	r.mu.RLock()
	fn, ok := r.applets[name]
	r.mu.RUnlock()
	if !ok {
		return fmt.Errorf("%w: %q (from %q)", ErrUnknownApplet, name, applet)
	}
	return fn(ctx, args, store, busAddr)
}

// DispatchArgv dispatches using a full argv slice where argv[0] selects the
// applet by basename and argv[1:] are passed as applet arguments.
func (r *Registry) DispatchArgv(
	ctx context.Context,
	argv []string,
	store *casv11.Store,
	busAddr string,
) error {
	if len(argv) == 0 {
		return fmt.Errorf("%w: empty argv", ErrUnknownApplet)
	}
	return r.Dispatch(ctx, argv[0], argv[1:], store, busAddr)
}

// ServeGocacheProgApplet wraps casv11.ServeGocacheProg as an AppletFunc over
// explicit reader/writer streams for in-process or pipe-based execution.
func ServeGocacheProgApplet(in io.Reader, out io.Writer) AppletFunc {
	return func(ctx context.Context, _ []string, store *casv11.Store, _ string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return casv11.ServeGocacheProg(store, in, out)
	}
}

func builtinGocacheProgApplet(ctx context.Context, args []string, store *casv11.Store, busAddr string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(args) > 0 && (args[0] == "serve" || args[0] == "--serve") {
		return casv11.ServeGocacheProg(store, os.Stdin, os.Stdout)
	}
	return recordAppletDescriptor("b8g-gocacheprog", args, store, busAddr)
}

func newBuiltinServiceApplet(name string) AppletFunc {
	return func(ctx context.Context, args []string, store *casv11.Store, busAddr string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return recordAppletDescriptor(name, args, store, busAddr)
	}
}

func recordAppletDescriptor(applet string, args []string, store *casv11.Store, busAddr string) error {
	desc := AppletDescriptor{
		Applet:   applet,
		BusAddr:  busAddr,
		ABIMagic: casv11.B8GAbiMagicV3,
		Args:     args,
	}
	payload, err := json.Marshal(desc)
	if err != nil {
		return fmt.Errorf("multicall: marshal descriptor for %s: %w", applet, err)
	}
	if _, _, err := store.Put(payload, false); err != nil {
		return fmt.Errorf("multicall: store descriptor for %s: %w", applet, err)
	}
	return nil
}
