package claims

import (
	"encoding/base64"
	"encoding/json"
	"regexp"

	"github.com/seawise-io/seawise-client/tunnelwire/wire"
)

// RouteSet JWS type and caps.
const (
	TypRouteSet = "sw-routeset+jws"
	MaxRoutes   = 250
	MaxFQDN     = 253
)

var (
	uuidRe  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	labelRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
)

// ValidUUID reports whether s is a canonical lower-case UUID.
func ValidUUID(s string) bool { return uuidRe.MatchString(s) }

// ValidFQDN reports whether s is a lower-case host name of 1..253 bytes
// made of LDH labels.
func ValidFQDN(s string) bool {
	if len(s) == 0 || len(s) > MaxFQDN {
		return false
	}
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '.' {
			if !labelRe.MatchString(s[start:i]) {
				return false
			}
			start = i + 1
		}
	}
	return true
}

// Route is one routed app.
type Route struct {
	AppID         string `json:"app_id"`
	FQDN          string `json:"fqdn"`
	Public        bool   `json:"public"`
	AccessVersion int64  `json:"access_version"`
}

// RouteSet is the verified payload of a RouteSet JWS.
type RouteSet struct {
	Edge      string  `json:"edge"`
	ServerID  string  `json:"server_id"`
	SessionID string  `json:"session_id"`
	Version   int64   `json:"version"`
	Routes    []Route `json:"routes"`
	IAT       int64   `json:"iat"`
}

// RouteSetExpect is what the agent knows from its session.
type RouteSetExpect struct {
	EdgeID      string // HelloAckBody.edge_id
	Signer      string // name of the edge key that signed the JWS
	ServerID    string // own server id
	SessionID   []byte // HelloAckBody.session_id
	LastVersion int64  // last applied version in this session, 0 for none
}

// CheckRouteSetSize refuses a RouteSet JWS over its cap.
func CheckRouteSetSize(jws string) error {
	if len(jws) > wire.MaxRouteSetJWS {
		return fail(CodeTooLarge)
	}
	return nil
}

// CheckRouteSet decodes a verified RouteSet payload and binds it to the
// session.
func CheckRouteSet(payload []byte, e RouteSetExpect) (*RouteSet, error) {
	var raw struct {
		Edge      string            `json:"edge"`
		ServerID  string            `json:"server_id"`
		SessionID string            `json:"session_id"`
		Version   int64             `json:"version"`
		Routes    []json.RawMessage `json:"routes"`
		IAT       int64             `json:"iat"`
	}
	if err := decodeObject(payload, &raw, []string{"edge", "server_id", "session_id", "version", "routes", "iat"}); err != nil {
		return nil, err
	}
	if !wire.ValidEdgeID(raw.Edge) || !ValidUUID(raw.ServerID) || raw.Version < 1 || !safeInt(raw.Version) || !safeInt(raw.IAT) {
		return nil, fail(CodeMalformed)
	}
	if len(raw.Routes) > MaxRoutes {
		return nil, fail(CodeTooManyRoutes)
	}
	rs := &RouteSet{Edge: raw.Edge, ServerID: raw.ServerID, SessionID: raw.SessionID, Version: raw.Version, IAT: raw.IAT, Routes: []Route{}}
	apps, hosts := map[string]bool{}, map[string]bool{}
	for _, r := range raw.Routes {
		var rt Route
		if err := decodeObject(r, &rt, []string{"app_id", "fqdn", "public", "access_version"}); err != nil {
			return nil, err
		}
		if !ValidUUID(rt.AppID) || !ValidFQDN(rt.FQDN) || !safeInt(rt.AccessVersion) || apps[rt.AppID] || hosts[rt.FQDN] {
			return nil, fail(CodeMalformed)
		}
		apps[rt.AppID], hosts[rt.FQDN] = true, true
		rs.Routes = append(rs.Routes, rt)
	}
	if rs.Edge != e.EdgeID || rs.Edge != e.Signer {
		return nil, fail(CodeWrongEdge)
	}
	if rs.ServerID != e.ServerID {
		return nil, fail(CodeWrongServer)
	}
	if rs.SessionID != base64.RawURLEncoding.EncodeToString(e.SessionID) {
		return nil, fail(CodeWrongSession)
	}
	if rs.Version <= e.LastVersion {
		return nil, fail(CodeRollback)
	}
	return rs, nil
}
