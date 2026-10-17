package controlplane

import (
	"strings"
	"testing"
)

func FuzzParseServiceList(f *testing.F) {
	f.Add([]byte(`[]`))
	f.Add([]byte(`null`))
	f.Add([]byte(`[{"id":"` + serviceID + `","name":"a","host":"h","port":80,"subdomain":"calm-otter"}]`))
	f.Add([]byte(`[{"id":"` + serviceID + `","name":"a","host":"h","port":1e3}]`))
	f.Add([]byte(`[null,{}]`))
	f.Fuzz(func(t *testing.T, data []byte) {
		out, err := parseServiceList(data)
		if err != nil {
			if KindOf(err) != Transient {
				t.Fatalf("parse error kind %v", KindOf(err))
			}
			return
		}
		if out == nil || len(out) > MaxListItems {
			t.Fatalf("bad result %v", out)
		}
		for _, s := range out {
			if !validUUID(s.ID) || !validName(s.Name) || !validHost(s.Host) || s.Port < 1 || s.Port > 65535 {
				t.Fatalf("invalid item accepted: %+v", s)
			}
			if s.Subdomain != "" && !ValidSubdomain(s.Subdomain) {
				t.Fatalf("invalid subdomain accepted: %q", s.Subdomain)
			}
		}
	})
}

func FuzzParseHeartbeat(f *testing.F) {
	f.Add([]byte(`{"status":"ok","next_heartbeat_ms":30000}`))
	f.Add([]byte(`{"status":"migrate","migrate_to":{"frp_server_addr":"frp-2.seawise.dev","frp_server_port":7000}}`))
	f.Add([]byte(`{"status":"ok","shard":{"frp_server_addr":"x.seawise.dev.evil","frp_server_port":1}}`))
	f.Add([]byte(`{"status":"ok","next_heartbeat_ms":-9223372036854775808}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		hb, err := parseHeartbeat(data, testDomains)
		if err != nil {
			return
		}
		if hb.NextHeartbeat < MinHeartbeat || hb.NextHeartbeat > MaxHeartbeat {
			t.Fatalf("interval %v out of range", hb.NextHeartbeat)
		}
		for _, ep := range []*Endpoint{hb.MigrateTo, hb.Shard} {
			if ep != nil && (!strings.HasSuffix(ep.Addr, ".seawise.dev") || ep.Port < 1 || ep.Port > 65535) {
				t.Fatalf("endpoint accepted: %+v", ep)
			}
		}
		if hb.Status == "migrate" && hb.MigrateTo == nil {
			t.Fatal("migrate without target")
		}
	})
}

func FuzzParsePairing(f *testing.F) {
	f.Add([]byte(`{"server_id":"` + serverID + `","frp_token":"t","frp_server_addr":"frp-1.seawise.dev","frp_server_port":7000,"frp_use_tls":true}`))
	f.Add([]byte(`{"server_id":"` + serverID + `","frp_token":"t\n","frp_server_addr":"seawise.dev","frp_server_port":7000,"frp_use_tls":false}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := parsePairing(data, testDomains)
		if err != nil {
			return
		}
		if !validUUID(p.ServerID) || !validToken(p.FRPToken) || !AllowedFRPHost(p.FRPServerAddr, testDomains) || p.FRPServerPort < 1 || p.FRPServerPort > 65535 {
			t.Fatalf("invalid pairing accepted: %+v", p)
		}
	})
}

func FuzzUnpairBody(f *testing.F) {
	f.Add([]byte(`{"action":"unpair","reason":"server_deleted"}`))
	f.Add([]byte(`{"action":"unpair"} trailing`))
	f.Add([]byte(`<html>`))
	f.Fuzz(func(t *testing.T, data []byte) {
		reason, ok := unpairBody(data, true)
		if !ok {
			return
		}
		if reason == "" || len(reason) > 64+4 || strings.ContainsFunc(reason, isControl) {
			t.Fatalf("removal from %q reason %q", data, reason)
		}
		if _, ok := unpairBody(data, false); ok {
			t.Fatal("non-JSON accepted")
		}
	})
}
