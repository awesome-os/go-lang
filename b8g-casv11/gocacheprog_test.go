package casv11

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestServeGocacheProgProtocol(t *testing.T) {
	store := NewStore(t.TempDir())
	actionID := []byte("0123456789abcdef0123456789abcdef")
	outputID := []byte("fedcba9876543210fedcba9876543210")
	payload := []byte("compiled-go-package-archive-bytes")

	var in bytes.Buffer
	enc := json.NewEncoder(&in)
	// 1. get (expect miss)
	_ = enc.Encode(GocacheRequest{ID: 1, Command: "get", ActionID: actionID})
	// 2. put (with base64 body line)
	_ = enc.Encode(GocacheRequest{ID: 2, Command: "put", ActionID: actionID, OutputID: outputID, BodySize: int64(len(payload))})
	_ = enc.Encode(base64.StdEncoding.EncodeToString(payload))
	// 3. get (expect hit pointing into v11/files/<xx>/<sha512>)
	_ = enc.Encode(GocacheRequest{ID: 3, Command: "get", ActionID: actionID})
	// 4. close
	_ = enc.Encode(GocacheRequest{ID: 4, Command: "close"})

	var out bytes.Buffer
	if err := ServeGocacheProg(store, &in, &out); err != nil {
		t.Fatalf("ServeGocacheProg: %v", err)
	}

	var resps []GocacheResponse
	dec := json.NewDecoder(&out)
	for dec.More() {
		var r GocacheResponse
		if err := dec.Decode(&r); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		resps = append(resps, r)
	}

	if len(resps) != 5 {
		t.Fatalf("expected 5 responses (handshake + 4 cmds), got %d", len(resps))
	}
	// Handshake
	if resps[0].ID != 0 || len(resps[0].KnownCommands) != 3 {
		t.Fatalf("bad handshake: %+v", resps[0])
	}
	// Miss
	if resps[1].ID != 1 || !resps[1].Miss {
		t.Fatalf("expected miss for ID=1, got %+v", resps[1])
	}
	// Put
	if resps[2].ID != 2 || resps[2].Err != "" || !strings.Contains(resps[2].DiskPath, "v11") {
		t.Fatalf("bad put response: %+v", resps[2])
	}
	// Hit
	if resps[3].ID != 3 || resps[3].Miss || resps[3].DiskPath != resps[2].DiskPath {
		t.Fatalf("expected hit matching put DiskPath, got %+v", resps[3])
	}
	if !bytes.Equal(resps[3].OutputID, outputID) || resps[3].Size != int64(len(payload)) {
		t.Fatalf("metadata mismatch: %+v", resps[3])
	}
	gotBytes, err := os.ReadFile(resps[3].DiskPath)
	if err != nil || !bytes.Equal(gotBytes, payload) {
		t.Fatalf("disk blob content mismatch: err=%v", err)
	}
	// Close
	if resps[4].ID != 4 || resps[4].Err != "" {
		t.Fatalf("bad close response: %+v", resps[4])
	}
}
