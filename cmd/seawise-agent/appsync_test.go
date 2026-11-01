package main

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/seawise/client/internal/appsync"
	"github.com/seawise/client/internal/store"
)

func TestAppSyncOffWithoutKeystore(t *testing.T) {
	st, err := store.Open(t.TempDir(), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	status, active, e := startAppSync(context.Background(), slog.Default(), st, nil, nil)
	if e != nil || active() {
		t.Fatal("app sync engine started without a keystore")
	}
	if s := status(); s.Mode != appsync.ModeOff || !strings.Contains(s.LastError, "app sync off") {
		t.Fatalf("status %+v", s)
	}
}
