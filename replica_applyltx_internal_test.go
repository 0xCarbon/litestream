package litestream

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/superfly/ltx"
)

// fakeLTXClient serves a single in-memory LTX file for applyLTXFile tests.
type fakeLTXClient struct {
	data io.ReadSeeker
}

func (c *fakeLTXClient) Type() string                                          { return "fake" }
func (c *fakeLTXClient) Init(context.Context) error                            { return nil }
func (c *fakeLTXClient) SetLogger(*slog.Logger)                                {}
func (c *fakeLTXClient) DeleteAll(context.Context) error                       { return nil }
func (c *fakeLTXClient) DeleteLTXFiles(context.Context, []*ltx.FileInfo) error { return nil }
func (c *fakeLTXClient) WriteLTXFile(context.Context, int, ltx.TXID, ltx.TXID, io.Reader) (*ltx.FileInfo, error) {
	return nil, os.ErrInvalid
}
func (c *fakeLTXClient) LTXFiles(context.Context, int, ltx.TXID, bool) (ltx.FileIterator, error) {
	return ltx.NewFileInfoSliceIterator(nil), nil
}
func (c *fakeLTXClient) OpenLTXFile(context.Context, int, ltx.TXID, ltx.TXID, int64, int64) (io.ReadCloser, error) {
	_, err := c.data.Seek(0, io.SeekStart)
	if err != nil {
		return nil, err
	}
	return io.NopCloser(c.data), nil
}

// buildPage1LTX encodes a snapshot LTX whose page 1 is filled with fill.
func buildPage1LTX(tb testing.TB, fill byte) *fakeLTXClient {
	tb.Helper()
	var buf bytes.Buffer
	enc, err := ltx.NewEncoder(&buf)
	if err != nil {
		tb.Fatal(err)
	}
	if err := enc.EncodeHeader(ltx.Header{
		Version:   ltx.Version,
		PageSize:  4096,
		Commit:    1,
		MinTXID:   1,
		MaxTXID:   1,
		Timestamp: time.Now().UnixMilli(),
		Flags:     ltx.HeaderFlagNoChecksum,
	}); err != nil {
		tb.Fatal(err)
	}
	page := bytes.Repeat([]byte{fill}, 4096)
	if err := enc.EncodePage(ltx.PageHeader{Pgno: 1}, page); err != nil {
		tb.Fatal(err)
	}
	if err := enc.Close(); err != nil {
		tb.Fatal(err)
	}
	return &fakeLTXClient{data: bytes.NewReader(buf.Bytes())}
}

// TestReplica_ApplyLTXFileSkipsJournalPatchForEncryptedDB guards follow-mode
// restore of SQLCipher databases: page 1 is ciphertext, so rewriting bytes
// 18-19 (and 24-27) corrupts the HMAC and makes the database unrecoverable.
func TestReplica_ApplyLTXFileSkipsJournalPatchForEncryptedDB(t *testing.T) {
	ctx := context.Background()

	for _, tc := range []struct {
		name        string
		keyBytes    []byte
		wantPatched bool
	}{
		{name: "plaintext", wantPatched: true},
		{name: "encrypted", keyBytes: bytes.Repeat([]byte{7}, 32)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := buildPage1LTX(t, 0x68)

			db := NewDB(filepath.Join(t.TempDir(), "db"))
			db.EncryptionKeyBytes = tc.keyBytes
			r := NewReplicaWithClient(db, client)
			r.MonitorEnabled = false
			db.Replica = r

			outPath := filepath.Join(t.TempDir(), "out.db")
			f, err := os.OpenFile(outPath, os.O_CREATE|os.O_RDWR, 0o644)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()

			if err := r.applyLTXFile(ctx, f, &ltx.FileInfo{Level: 0, MinTXID: 1, MaxTXID: 1}, 4096); err != nil {
				t.Fatalf("applyLTXFile: %v", err)
			}

			buf := make([]byte, 32)
			if _, err := f.ReadAt(buf, 0); err != nil {
				t.Fatal(err)
			}
			if tc.wantPatched {
				if buf[18] != 0x01 || buf[19] != 0x01 {
					t.Fatalf("plaintext: page-1 journal patch not applied, bytes 18-19 = %x %x", buf[18], buf[19])
				}
			} else if buf[18] != 0x68 || buf[19] != 0x68 {
				t.Fatalf("encrypted: page-1 bytes 18-19 must be untouched, got %x %x", buf[18], buf[19])
			}
		})
	}
}
