package main

import (
	"log/slog"
	"testing"
)

func TestParseArgs(t *testing.T) {
	for _, c := range []struct {
		args []string
		port int
		help bool
		bad  bool
	}{
		{nil, 0, false, false},
		{[]string{"serve"}, 0, false, false},
		{[]string{"serve", "--port", "9000"}, 9000, false, false},
		{[]string{"serve", "-p", "9001"}, 9001, false, false},
		{[]string{"--port=9002"}, 9002, false, false},
		{[]string{"-p9003"}, 9003, false, false},
		{[]string{"-p=9004"}, 9004, false, false},
		{[]string{"--help"}, 0, true, false},
		{[]string{"serve", "help"}, 0, true, false},
		{[]string{"-p"}, 0, false, true},
		{[]string{"--port", "0"}, 0, false, true},
		{[]string{"--port", "65536"}, 0, false, true},
		{[]string{"--port", "abc"}, 0, false, true},
		{[]string{"run"}, 0, false, true},
		{[]string{"serve", "serve"}, 0, false, true},
	} {
		o, err := parseArgs(c.args)
		if (err != nil) != c.bad || (!c.bad && (o.port != c.port || o.help != c.help)) {
			t.Errorf("%q: %+v %v", c.args, o, err)
		}
	}
}

func TestAdminPort(t *testing.T) {
	if p, err := adminPort(0, "", 8082); p != 8082 || err != nil {
		t.Fatal(p, err)
	}
	if p, err := adminPort(0, "9100", 8082); p != 9100 || err != nil {
		t.Fatal(p, err)
	}
	if p, err := adminPort(9200, "9100", 8082); p != 9200 || err != nil {
		t.Fatal("the flag wins over SEAWISE_PORT", p, err)
	}
	for _, bad := range []string{"0", "x", "70000"} {
		if _, err := adminPort(0, bad, 8082); err == nil {
			t.Fatalf("SEAWISE_PORT=%s accepted", bad)
		}
	}
}

func TestLogLevel(t *testing.T) {
	for v, want := range map[string]slog.Level{"": slog.LevelInfo, "debug": slog.LevelDebug, " WARN ": slog.LevelWarn,
		"warning": slog.LevelWarn, "error": slog.LevelError, "trace": slog.LevelInfo} {
		if got := logLevel(v); got != want {
			t.Errorf("%q: %v", v, got)
		}
	}
}
