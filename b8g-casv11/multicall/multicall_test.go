package multicall

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sync"
	"testing"

	casv11 "github.com/awesome-os/go-lang/b8g-casv11"
)

func TestDefaultBusAddress(t *testing.T) {
	tests := []struct {
		goos string
		want string
	}{
		{goos: "windows", want: `\\.\pipe\b8g-host-bus`},
		{goos: "Windows", want: `\\.\pipe\b8g-host-bus`},
		{goos: "linux", want: "/run/b8g/host-bus.sock"},
		{goos: "darwin", want: "/run/b8g/host-bus.sock"},
		{goos: "freebsd", want: "/run/b8g/host-bus.sock"},
	}

	for _, tc := range tests {
		got := DefaultBusAddress(tc.goos)
		if got != tc.want {
			t.Errorf("DefaultBusAddress(%q) = %q, want %q", tc.goos, got, tc.want)
		}
		if err := ValidateBusAddress(got); err != nil {
			t.Errorf("ValidateBusAddress(DefaultBusAddress(%q)) unexpected error: %v", tc.goos, err)
		}
	}
}

func TestValidateBusAddress_B8G016Rejection(t *testing.T) {
	rejected := []string{
		"http://127.0.0.1:8080",
		"https://127.0.0.1:8443",
		"http://localhost:3000",
		"https://LOCALHOST:9000/rpc",
		"127.0.0.1:8080",
		"localhost:5000",
		"http://example.internal/bus",
		"https://example.internal/bus",
		"[::1]:8080",
		"::1",
	}

	for _, addr := range rejected {
		err := ValidateBusAddress(addr)
		if !errors.Is(err, ErrLoopbackHTTPForbidden) {
			t.Errorf("ValidateBusAddress(%q) = %v, want ErrLoopbackHTTPForbidden", addr, err)
		}
	}

	if err := ValidateBusAddress("   "); !errors.Is(err, ErrEmptyBusAddress) {
		t.Errorf("ValidateBusAddress(whitespace) = %v, want ErrEmptyBusAddress", err)
	}

	valid := []string{
		WindowsBusAddress,
		UnixBusAddress,
		`\\.\pipe\sectium-dev`,
		"/tmp/sectium-dev.sock",
		"b8g-arena://B8G_ARENA_V1/host-bus",
	}
	for _, addr := range valid {
		if err := ValidateBusAddress(addr); err != nil {
			t.Errorf("ValidateBusAddress(%q) unexpected error: %v", addr, err)
		}
	}
}

func TestResolveAppletName_Argv0Basename(t *testing.T) {
	tests := []struct {
		argv0 string
		want  string
	}{
		{argv0: "gitaly.exe", want: "gitaly"},
		{argv0: "GITALY.EXE", want: "gitaly"},
		{argv0: `C:\Awesome-OS\bin\gitaly.exe`, want: "gitaly"},
		{argv0: "/usr/bin/gitlab-pages", want: "gitlab-pages"},
		{argv0: "/usr/local/bin/gitlab-shell", want: "gitlab-shell"},
		{argv0: "./workhorse", want: "workhorse"},
		{argv0: `.\b8g-gocacheprog.exe`, want: "b8g-gocacheprog"},
		{argv0: "gitlab-runner", want: "gitlab-runner"},
		{argv0: "   ", want: ""},
	}

	for _, tc := range tests {
		got := ResolveAppletName(tc.argv0)
		if got != tc.want {
			t.Errorf("ResolveAppletName(%q) = %q, want %q", tc.argv0, got, tc.want)
		}
	}
}

func TestDefaultRegistryContainsAllRequiredApplets(t *testing.T) {
	reg := NewRegistry()
	got := reg.Applets()
	want := []string{
		"b8g-gocacheprog",
		"gitaly",
		"gitlab-pages",
		"gitlab-runner",
		"gitlab-shell",
		"workhorse",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("NewRegistry().Applets() = %v, want %v", got, want)
	}
}

func TestDispatch_Argv0AndB8G016Enforcement(t *testing.T) {
	reg := NewRegistry()
	store := casv11.NewStore(t.TempDir())
	busAddr := DefaultBusAddress("linux")

	// Reject loopback HTTP during dispatch even for a valid applet.
	err := reg.Dispatch(context.Background(), "gitaly.exe", nil, store, "http://127.0.0.1:8080")
	if !errors.Is(err, ErrLoopbackHTTPForbidden) {
		t.Fatalf("expected ErrLoopbackHTTPForbidden, got %v", err)
	}

	// Reject nil store.
	if err := reg.Dispatch(context.Background(), "gitaly", nil, nil, busAddr); !errors.Is(err, ErrNilStore) {
		t.Fatalf("expected ErrNilStore, got %v", err)
	}

	// Reject unknown applet.
	if err := reg.Dispatch(context.Background(), "/usr/bin/nonexistent", nil, store, busAddr); !errors.Is(err, ErrUnknownApplet) {
		t.Fatalf("expected ErrUnknownApplet, got %v", err)
	}

	// Dispatch built-in applets via BusyBox-style argv[0] paths.
	invocations := [][]string{
		{"gitaly.exe", "--listen-bus"},
		{"/usr/bin/gitlab-pages", "--serve-cas"},
		{`C:\bin\gitlab-shell.exe`},
		{"/opt/b8g/gitlab-runner"},
		{"workhorse.exe"},
		{"b8g-gocacheprog"},
	}

	for _, argv := range invocations {
		if err := reg.DispatchArgv(context.Background(), argv, store, busAddr); err != nil {
			t.Fatalf("DispatchArgv(%v) failed: %v", argv, err)
		}

		expectedDesc := AppletDescriptor{
			Applet:   ResolveAppletName(argv[0]),
			BusAddr:  busAddr,
			ABIMagic: casv11.B8GAbiMagicV3,
			Args:     argv[1:],
		}
		payload, err := json.Marshal(expectedDesc)
		if err != nil {
			t.Fatalf("marshal expected descriptor: %v", err)
		}
		digest := casv11.DigestBytes(payload)
		if !store.Has(digest, false) {
			t.Errorf("shared store missing descriptor object for %s", expectedDesc.Applet)
		}
	}
}

func TestDispatch_SharedStoreZeroDuplicateState(t *testing.T) {
	reg := NewRegistry()
	sharedStore := casv11.NewStore(t.TempDir())
	busAddr := DefaultBusAddress("windows")

	var (
		mu             sync.Mutex
		seenStorePtrs  = make(map[*casv11.Store]struct{})
		writtenDigests = make(map[string]string)
	)

	// Register custom handlers for gitaly (writer) and gitlab-pages (reader)
	// plus workhorse (verifier) to prove all applets operate on the exact same
	// *casv11.Store pointer and share deduplicated state without duplication.
	const sharedPayload = "awesome-os-shared-casv11-artifact-zero-dup"
	expectedDigest := casv11.DigestBytes([]byte(sharedPayload))

	reg.Register("gitaly", func(ctx context.Context, args []string, s *casv11.Store, bus string) error {
		mu.Lock()
		seenStorePtrs[s] = struct{}{}
		mu.Unlock()
		if bus != busAddr {
			t.Errorf("gitaly got bus %q, want %q", bus, busAddr)
		}
		d, _, err := s.Put([]byte(sharedPayload), false)
		if err != nil {
			return err
		}
		mu.Lock()
		writtenDigests["gitaly"] = d
		mu.Unlock()
		return nil
	})

	reg.Register("gitlab-pages", func(ctx context.Context, args []string, s *casv11.Store, bus string) error {
		mu.Lock()
		seenStorePtrs[s] = struct{}{}
		mu.Unlock()
		got, err := s.Get(expectedDigest, false)
		if err != nil {
			return err
		}
		if string(got) != sharedPayload {
			t.Errorf("gitlab-pages read %q, want %q", string(got), sharedPayload)
		}
		return nil
	})

	reg.Register("workhorse", func(ctx context.Context, args []string, s *casv11.Store, bus string) error {
		mu.Lock()
		seenStorePtrs[s] = struct{}{}
		mu.Unlock()
		return s.Verify(expectedDigest, false)
	})

	if err := reg.Dispatch(context.Background(), `C:\bin\gitaly.exe`, nil, sharedStore, busAddr); err != nil {
		t.Fatalf("dispatch gitaly failed: %v", err)
	}
	if err := reg.Dispatch(context.Background(), "/usr/bin/gitlab-pages", nil, sharedStore, busAddr); err != nil {
		t.Fatalf("dispatch gitlab-pages failed: %v", err)
	}
	if err := reg.Dispatch(context.Background(), "workhorse", nil, sharedStore, busAddr); err != nil {
		t.Fatalf("dispatch workhorse failed: %v", err)
	}

	if len(seenStorePtrs) != 1 {
		t.Fatalf("expected exactly 1 shared *casv11.Store instance, saw %d", len(seenStorePtrs))
	}
	if _, ok := seenStorePtrs[sharedStore]; !ok {
		t.Fatalf("dispatched applets did not receive the caller's sharedStore pointer")
	}
	if writtenDigests["gitaly"] != expectedDigest {
		t.Fatalf("gitaly digest = %q, want %q", writtenDigests["gitaly"], expectedDigest)
	}
}

func TestServeGocacheProgApplet_SharedStore(t *testing.T) {
	reg := NewRegistry()
	sharedStore := casv11.NewStore(t.TempDir())

	var in bytes.Buffer
	in.WriteString(`{"ID":1,"Command":"close"}` + "\n")
	var out bytes.Buffer

	reg.Register("b8g-gocacheprog", ServeGocacheProgApplet(&in, &out))

	if err := reg.Dispatch(context.Background(), "b8g-gocacheprog.exe", nil, sharedStore, ""); err != nil {
		t.Fatalf("dispatch b8g-gocacheprog failed: %v", err)
	}
	if !bytes.Contains(out.Bytes(), []byte(`"KnownCommands":["get","put","close"]`)) {
		t.Fatalf("unexpected gocacheprog handshake output: %s", out.String())
	}
}
