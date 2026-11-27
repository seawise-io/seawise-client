package testedge

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	pb "github.com/seawise-io/seawise-client/tunnelwire/tunnelpb"
	"github.com/seawise-io/seawise-client/tunnelwire/wire"

	"github.com/seawise/client/internal/protocol"
)

// answer is the device API's answer to a call, the same on both carriers.
func (e *Edge) answer(method pb.DeviceMethod, body []byte, dpop string) (int, []byte) {
	if w := e.cfg.DPoPWindow; w > 0 {
		if iat, ok := proofIAT(dpop); !ok || time.Unix(iat, 0).Sub(e.Now()).Abs() > w {
			e.event(Event{Kind: "dpop_iat_refused", Detail: method.String()})
			return http.StatusUnauthorized, []byte(`{"error":"invalid_proof"}`)
		}
	}
	switch method {
	case pb.DeviceMethod_LIST_APPS:
		type app struct {
			ID              string  `json:"id"`
			LocalID         string  `json:"local_id"`
			Name            string  `json:"name"`
			Subdomain       string  `json:"subdomain"`
			Host            string  `json:"host"`
			Port            int     `json:"port"`
			Status          string  `json:"status"`
			IconURL         *string `json:"icon_url"`
			PublicRequested bool    `json:"public_requested"`
			PublicLocal     bool    `json:"public_local"`
			CreatedAt       string  `json:"created_at"`
		}
		apps := make([]app, 0, len(e.cfg.Apps))
		for _, a := range e.cfg.Apps {
			apps = append(apps, app{ID: a.ID, LocalID: a.LocalID, Name: a.Name, Subdomain: a.Subdomain, Host: a.Host, Port: a.Port,
				Status: "online", CreatedAt: "2026-10-01T12:00:00.000Z"})
		}
		b, _ := json.Marshal(map[string]any{"apps": apps, "deleted": []string{}})
		return http.StatusOK, b
	case pb.DeviceMethod_REPORT_HEALTH:
		var req struct {
			Apps []json.RawMessage `json:"apps"`
		}
		_ = json.Unmarshal(body, &req)
		return http.StatusOK, fmt.Appendf(nil, `{"matched":%d,"changed":0}`, len(req.Apps))
	case pb.DeviceMethod_REGISTER_APPS:
		var req struct {
			Apps []struct {
				LocalID string `json:"local_id"`
			} `json:"apps"`
		}
		_ = json.Unmarshal(body, &req)
		type item struct {
			LocalID   string `json:"local_id"`
			ID        string `json:"id"`
			Result    string `json:"result"`
			Subdomain string `json:"subdomain"`
		}
		items := []item{}
		for _, r := range req.Apps {
			for _, a := range e.cfg.Apps {
				if a.LocalID == r.LocalID {
					items = append(items, item{LocalID: a.LocalID, ID: a.ID, Result: "unchanged", Subdomain: a.Subdomain})
				}
			}
		}
		b, _ := json.Marshal(map[string]any{"items": items})
		return http.StatusOK, b
	case pb.DeviceMethod_DELETE_APPS:
		return http.StatusOK, []byte(`{"results":[]}`)
	case pb.DeviceMethod_SIGNED_TIME:
		var req struct {
			Nonce string `json:"nonce"`
		}
		_ = json.Unmarshal(body, &req)
		pub := e.cfg.DeviceKey()
		if pub == nil {
			return http.StatusUnauthorized, []byte(`{"error":"invalid_proof"}`)
		}
		tok, err := protocol.NewKeyed(e.cfg.Keys.Control, protocol.TypState, map[string]any{"server_id": e.cfg.ServerID,
			"key_id": protocol.KeyID(pub), "time": e.Now().Unix(), "nonce": req.Nonce, "device_status": "active", "account_status": "active"})
		if err != nil {
			return http.StatusInternalServerError, nil
		}
		b, _ := json.Marshal(map[string]any{"data": map[string]any{"signed_time": tok, "flags": nil}})
		return http.StatusOK, b
	}
	return http.StatusNotFound, []byte(`{"error":"not_found"}`)
}

// proofIAT reads the iat of a DPoP proof without checking it.
func proofIAT(proof string) (int64, bool) {
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		return 0, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return 0, false
	}
	var c struct {
		IAT int64 `json:"iat"`
	}
	if json.Unmarshal(raw, &c) != nil || c.IAT == 0 {
		return 0, false
	}
	return c.IAT, true
}

// APIHandler serves the device API's HTTPS twins of the device calls, and
// files (the update repository) at /tuf/ when files is set.
func (e *Edge) APIHandler(files http.Handler) http.Handler {
	mux := http.NewServeMux()
	if files != nil {
		mux.Handle("/tuf/", http.StripPrefix("/tuf", files))
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		for m, route := range wire.DeviceRoutes {
			if route.Method != r.Method || route.Path != r.URL.Path {
				continue
			}
			body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
			status, out := e.answer(m, body, r.Header.Get("DPoP"))
			e.countCall("https:" + m.String())
			e.event(Event{Kind: "https_call", Detail: fmt.Sprintf("%s %d", m, status)})
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("DPoP-Nonce", newNonce())
			w.WriteHeader(status)
			_, _ = w.Write(out)
			return
		}
		http.NotFound(w, r)
	})
	return mux
}

// APITLS is the TLS configuration of the device API, with a certificate
// for APIHost that follows the edge's clock.
func (e *Edge) APITLS() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		return e.cfg.CA.Leaf(e.cfg.APIHost, e.Now(), e.cfg.CertAge)
	}}
}
