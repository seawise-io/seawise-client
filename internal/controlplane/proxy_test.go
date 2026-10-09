package controlplane

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

func TestDefaultTransportUsesProxyFromEnvironment(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	seen := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		line, _ := bufio.NewReader(c).ReadString('\n')
		seen <- strings.TrimSpace(line)
	}()
	env := map[string]string{"HTTPS_PROXY": "http://" + ln.Addr().String()}
	c, err := New(Config{
		BaseURL: "https://api.example.invalid", Token: func() string { return token },
		Getenv: func(k string) string { return env[k] },
		Sleep:  func(context.Context, time.Duration) error { return context.Canceled },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _ = c.Heartbeat(ctx, serverID, HeartbeatRequest{})
	select {
	case got := <-seen:
		if got != "CONNECT api.example.invalid:443 HTTP/1.1" {
			t.Fatalf("proxy saw %q", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("request did not go through the proxy")
	}
}
