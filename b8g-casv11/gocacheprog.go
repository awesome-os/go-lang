package casv11

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// GocacheRequest mirrors Go's cmd/go/internal/cacheprog.Request wire format.
type GocacheRequest struct {
	ID       int64  `json:"ID"`
	Command  string `json:"Command"`
	ActionID []byte `json:"ActionID,omitempty"`
	OutputID []byte `json:"OutputID,omitempty"`
	BodySize int64  `json:"BodySize,omitempty"`
}

// GocacheResponse mirrors Go's cmd/go/internal/cacheprog.Response wire format.
type GocacheResponse struct {
	ID            int64      `json:"ID"`
	Err           string     `json:"Err,omitempty"`
	KnownCommands []string   `json:"KnownCommands,omitempty"`
	Miss          bool       `json:"Miss,omitempty"`
	OutputID      []byte     `json:"OutputID,omitempty"`
	Size          int64      `json:"Size,omitempty"`
	Time          *time.Time `json:"Time,omitempty"`
	DiskPath      string     `json:"DiskPath,omitempty"`
}

type actionRecord struct {
	OutputID []byte    `json:"outputId"`
	SHA512   string    `json:"sha512"`
	Size     int64     `json:"size"`
	Time     time.Time `json:"time"`
}

func (s *Store) actionIndexPath(actionID []byte) string {
	h := hex.EncodeToString(actionID)
	prefix := "00"
	if len(h) >= 2 {
		prefix = h[:2]
	}
	return filepath.Join(s.Root, StoreLayoutVersion, "go-actions", prefix, h+".json")
}

// ServeGocacheProg implements Go's GOCACHEPROG JSON-lines protocol backed directly
// by the unified Awesome-OS v11/files/00..ff/<sha512> CAS store.
func ServeGocacheProg(store *Store, r io.Reader, w io.Writer) error {
	dec := json.NewDecoder(bufio.NewReaderSize(r, 256*1024))
	bw := bufio.NewWriterSize(w, 256*1024)
	enc := json.NewEncoder(bw)

	writeResp := func(resp GocacheResponse) error {
		if err := enc.Encode(resp); err != nil {
			return err
		}
		return bw.Flush()
	}

	// Initial capability advertisement (ID == 0).
	if err := writeResp(GocacheResponse{
		ID:            0,
		KnownCommands: []string{"get", "put", "close"},
	}); err != nil {
		return fmt.Errorf("casv11 gocacheprog handshake: %w", err)
	}

	for {
		var req GocacheRequest
		if err := dec.Decode(&req); err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("casv11 gocacheprog decode request: %w", err)
		}

		switch req.Command {
		case "close":
			return writeResp(GocacheResponse{ID: req.ID})

		case "get":
			recPath := store.actionIndexPath(req.ActionID)
			raw, err := os.ReadFile(recPath)
			if err != nil {
				if err := writeResp(GocacheResponse{ID: req.ID, Miss: true}); err != nil {
					return err
				}
				continue
			}
			var rec actionRecord
			if err := json.Unmarshal(raw, &rec); err != nil {
				if err := writeResp(GocacheResponse{ID: req.ID, Miss: true}); err != nil {
					return err
				}
				continue
			}
			diskPath, err := store.ObjectPath(rec.SHA512, false)
			if err != nil {
				if err := writeResp(GocacheResponse{ID: req.ID, Miss: true}); err != nil {
					return err
				}
				continue
			}
			if _, err := os.Stat(diskPath); err != nil {
				if err := writeResp(GocacheResponse{ID: req.ID, Miss: true}); err != nil {
					return err
				}
				continue
			}
			t := rec.Time
			if err := writeResp(GocacheResponse{
				ID:       req.ID,
				OutputID: rec.OutputID,
				Size:     rec.Size,
				Time:     &t,
				DiskPath: diskPath,
			}); err != nil {
				return err
			}

		case "put":
			var body []byte
			if req.BodySize > 0 {
				var b64 string
				if err := dec.Decode(&b64); err != nil {
					return fmt.Errorf("casv11 gocacheprog decode put body: %w", err)
				}
				decoded, err := base64.StdEncoding.DecodeString(b64)
				if err != nil {
					if err := writeResp(GocacheResponse{ID: req.ID, Err: err.Error()}); err != nil {
						return err
					}
					continue
				}
				body = decoded
			}

			digest, diskPath, err := store.Put(body, false)
			if err != nil {
				if err := writeResp(GocacheResponse{ID: req.ID, Err: err.Error()}); err != nil {
					return err
				}
				continue
			}

			rec := actionRecord{
				OutputID: req.OutputID,
				SHA512:   digest,
				Size:     int64(len(body)),
				Time:     time.Now().UTC(),
			}
			recBytes, err := json.Marshal(rec)
			if err != nil {
				if err := writeResp(GocacheResponse{ID: req.ID, Err: err.Error()}); err != nil {
					return err
				}
				continue
			}
			recPath := store.actionIndexPath(req.ActionID)
			if err := os.MkdirAll(filepath.Dir(recPath), 0o755); err != nil {
				if err := writeResp(GocacheResponse{ID: req.ID, Err: err.Error()}); err != nil {
					return err
				}
				continue
			}
			if err := os.WriteFile(recPath, recBytes, 0o644); err != nil {
				if err := writeResp(GocacheResponse{ID: req.ID, Err: err.Error()}); err != nil {
					return err
				}
				continue
			}

			if err := writeResp(GocacheResponse{
				ID:       req.ID,
				DiskPath: diskPath,
			}); err != nil {
				return err
			}

		default:
			if err := writeResp(GocacheResponse{
				ID:  req.ID,
				Err: fmt.Sprintf("unknown command %q", req.Command),
			}); err != nil {
				return err
			}
		}
	}
}
