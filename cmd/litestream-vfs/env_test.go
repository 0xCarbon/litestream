//go:build vfs && SQLITE3VFS_LOADABLE_EXT

package main

import "testing"

func TestEnvFlag(t *testing.T) {
	t.Setenv("LITESTREAM_SKIP_JOURNAL_PATCH", "TRUE")
	if !envFlag("LITESTREAM_SKIP_JOURNAL_PATCH") {
		t.Fatal("expected case-insensitive true")
	}
	t.Setenv("LITESTREAM_WRITE_ENABLED", "false")
	if envFlag("LITESTREAM_WRITE_ENABLED") {
		t.Fatal("expected false")
	}
	t.Setenv("LITESTREAM_UNSET", "")
	if envFlag("LITESTREAM_UNSET") {
		t.Fatal("expected unset to be false")
	}
}
