package litestream

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/0xCarbon/go-sqlite3"
	"github.com/superfly/ltx"
)

// normalizeEncryptionKey adapts a key string for the driver's raw
// `PRAGMA key = %s;` interpolation. SQLite's PRAGMA grammar accepts only a
// string literal on the right-hand side, so a bare blob literal (x'…') or a
// bare passphrase is a syntax error. Wrap the common bare blob form in
// double quotes — the SQLCipher raw-key convention — and pass quoted values
// through unchanged.
func normalizeEncryptionKey(key string) string {
	if key != "" && key[0] == '"' {
		return key
	}
	if m := blobKeyRe.FindStringSubmatch(key); m != nil {
		return "\"" + key + "\""
	}
	return key
}

var blobKeyRe = regexp.MustCompile(`^x'[0-9a-fA-F]+'$`)

// newSQLiteDriver builds a 0xCarbon/go-sqlite3 (mattn-lineage) driver bound to one database's
// SQLCipher key. The key is applied as the first statement of every new
// connection; the connect hook applies Litestream's per-connection settings.
func newSQLiteDriver(encryptionKey string, encryptionKeyBytes []byte) *sqlite3.SQLiteDriver {
	return &sqlite3.SQLiteDriver{
		EncryptionKey: normalizeEncryptionKey(encryptionKey),
		// EncryptionKeyBytes takes precedence over EncryptionKey when set.
		// Clone so the caller may zero its slice after opening; the driver
		// keeps opening connections for the pool's lifetime.
		EncryptionKeyBytes: bytes.Clone(encryptionKeyBytes),
		ConnectHook: func(conn *sqlite3.SQLiteConn) error {
			if err := conn.SetFileControlInt("main", sqlite3.SQLITE_FCNTL_PERSIST_WAL, 1); err != nil {
				return fmt.Errorf("cannot set file control: %w", err)
			}
			// Litestream owns checkpointing; disable SQLite's automatic WAL
			// checkpoints (upstream disables this via modernc's _pragma= DSN,
			// which the go-sqlite3 fork does not support).
			if _, err := conn.Exec("PRAGMA wal_autocheckpoint = 0;", nil); err != nil {
				return fmt.Errorf("cannot disable wal_autocheckpoint: %w", err)
			}
			return nil
		},
	}
}

// sqliteConnector adapts a *sqlite3.SQLiteDriver and a DSN to the
// database/sql Connector interface. Each DB opens its pool with
// sql.OpenDB instead of a global sql.Register name: registrations are
// never removed, so a registry would retain key material for the
// process lifetime and leak one entry per open/close cycle.
type sqliteConnector struct {
	drv *sqlite3.SQLiteDriver
	dsn string
}

func (c *sqliteConnector) Connect(context.Context) (driver.Conn, error) {
	return c.drv.Open(c.dsn)
}

func (c *sqliteConnector) Driver() driver.Driver { return c.drv }

// newSQLitePool builds a connection pool around a driver built by
// newSQLiteDriver, so every connection carries the SQLCipher key and
// Litestream's per-connection settings.
func newSQLitePool(drv *sqlite3.SQLiteDriver, dsn string) *sql.DB {
	return sql.OpenDB(&sqliteConnector{drv: drv, dsn: dsn})
}

// Naming constants.
const (
	MetaDirSuffix = "-litestream"
)

// SQLite checkpoint modes.
const (
	CheckpointModePassive  = "PASSIVE"
	CheckpointModeFull     = "FULL"
	CheckpointModeRestart  = "RESTART"
	CheckpointModeTruncate = "TRUNCATE"
)

// Litestream errors.
var (
	ErrNoSnapshots      = errors.New("no snapshots available")
	ErrChecksumMismatch = errors.New("invalid replica, checksum mismatch")
	ErrLTXCorrupted     = errors.New("ltx file corrupted")
	ErrLTXMissing       = errors.New("ltx file missing")
	ErrDiskFull         = errors.New("disk full")
)

// LTXError provides detailed context for LTX file errors with recovery hints.
type LTXError struct {
	Op      string // Operation that failed (e.g., "open", "read", "validate")
	Path    string // File path
	Level   int    // LTX level (0 = L0, etc.)
	MinTXID uint64 // Minimum transaction ID
	MaxTXID uint64 // Maximum transaction ID
	Err     error  // Underlying error
	Hint    string // Recovery hint for users
}

func (e *LTXError) Error() string {
	if e.Path != "" {
		return e.Op + " ltx file " + e.Path + ": " + e.Err.Error()
	}
	return e.Op + " ltx file: " + e.Err.Error()
}

func (e *LTXError) Unwrap() error { return e.Err }

// IsAutoRecoverable reports whether the underlying error indicates local state
// corruption that can be fixed by resetting and re-downloading from remote.
// Returns false for transient OS errors (EMFILE, EIO, EACCES) that should be
// retried with backoff instead.
func (e *LTXError) IsAutoRecoverable() bool {
	if os.IsNotExist(e.Err) || errors.Is(e.Err, ErrLTXMissing) {
		return true
	}
	if errors.Is(e.Err, ErrLTXCorrupted) || errors.Is(e.Err, ErrChecksumMismatch) {
		return true
	}
	return false
}

// NewLTXError creates a new LTX error with appropriate hints based on the error type.
func NewLTXError(op, path string, level int, minTXID, maxTXID uint64, err error) *LTXError {
	ltxErr := &LTXError{
		Op:      op,
		Path:    path,
		Level:   level,
		MinTXID: minTXID,
		MaxTXID: maxTXID,
		Err:     err,
	}

	// Set appropriate hint based on error type
	if os.IsNotExist(err) || errors.Is(err, ErrLTXMissing) {
		ltxErr.Hint = "LTX file is missing. This can happen after VACUUM, manual checkpoint, or state corruption. " +
			"Run 'litestream reset <db>' or delete the .sqlite-litestream directory and restart."
	} else if errors.Is(err, ErrLTXCorrupted) || errors.Is(err, ErrChecksumMismatch) {
		ltxErr.Hint = "LTX file is corrupted. Delete the .sqlite-litestream directory and restart to recover from replica."
	}

	return ltxErr
}

// SQLite WAL constants.
const (
	WALHeaderChecksumOffset      = 24
	WALFrameHeaderChecksumOffset = 16
)

var (
	// LogWriter is the destination writer for all logging.
	LogWriter = os.Stdout

	// LogFlags are the flags passed to log.New().
	LogFlags = 0
)

// Checksum computes a running SQLite checksum over a byte slice.
func Checksum(bo binary.ByteOrder, s0, s1 uint32, b []byte) (uint32, uint32) {
	assert(len(b)%8 == 0, "misaligned checksum byte slice")

	// Iterate over 8-byte units and compute checksum.
	for i := 0; i < len(b); i += 8 {
		s0 += bo.Uint32(b[i:]) + s1
		s1 += bo.Uint32(b[i+4:]) + s0
	}
	return s0, s1
}

const (
	// WALHeaderSize is the size of the WAL header, in bytes.
	WALHeaderSize = 32

	// WALFrameHeaderSize is the size of the WAL frame header, in bytes.
	WALFrameHeaderSize = 24
)

// rollback rolls back tx. Ignores already-rolled-back errors.
func rollback(tx *sql.Tx) error {
	if err := tx.Rollback(); err != nil && !strings.Contains(err.Error(), `transaction has already been committed or rolled back`) {
		return err
	}
	return nil
}

// readWALHeader returns the header read from a WAL file.
func readWALHeader(filename string) ([]byte, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	buf := make([]byte, WALHeaderSize)
	n, err := io.ReadFull(f, buf)
	return buf[:n], err
}

// readWALFileAt reads a slice from a file. Do not use this with database files
// as it causes problems with non-OFD locks.
func readWALFileAt(filename string, offset, n int64) ([]byte, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	buf := make([]byte, n)
	if n, err := f.ReadAt(buf, offset); err != nil {
		return buf[:n], err
	} else if n < len(buf) {
		return buf[:n], io.ErrUnexpectedEOF
	}
	return buf, nil
}

// removeTmpFiles recursively finds and removes .tmp files.
func removeTmpFiles(root string) error {
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		switch {
		case err != nil:
			return nil // skip errored files
		case info.IsDir():
			return nil // skip directories
		case !strings.HasSuffix(path, ".tmp"):
			return nil // skip non-temp files
		default:
			return os.Remove(path)
		}
	})
}

// LTXDir returns the path to an LTX directory.
func LTXDir(root string) string {
	return path.Join(root, "ltx")
}

// LTXLevelDir returns the path to an LTX level directory.
func LTXLevelDir(root string, level int) string {
	return path.Join(LTXDir(root), strconv.Itoa(level))
}

// LTXFilePath returns the path to a single LTX file.
func LTXFilePath(root string, level int, minTXID, maxTXID ltx.TXID) string {
	return path.Join(LTXLevelDir(root, level), ltx.FormatFilename(minTXID, maxTXID))
}

func assert(condition bool, message string) {
	if !condition {
		panic("assertion failed: " + message)
	}
}
