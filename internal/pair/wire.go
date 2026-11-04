package pair

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/seawise-io/seawise-client/tunnelwire/claims"

	"github.com/seawise/client/internal/devicecall"
)

// Device API paths of the device flow.
const (
	PathRequest  = "/api/servers/pair/request"
	PathStatus   = "/api/servers/pair/status"
	PathComplete = "/api/servers/pair/complete"
	PathCancel   = "/api/servers/pair/cancel"
)

const (
	maxName = 100
	// maxCodeLife bounds how long a code is polled, whatever the server says.
	maxCodeLife = 20 * time.Minute
)

var (
	userCodeRe   = regexp.MustCompile(`^[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{10}$`)
	deviceCodeRe = regexp.MustCompile(`^[0-9a-f]{32}$`)
	errAnswer    = errors.New("malformed answer")
)

// data returns the object in {"data": {...}}, the only member allowed.
func data(raw []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil, errAnswer
	}
	if t, err := dec.Token(); err != nil || t != "data" {
		return nil, errAnswer
	}
	var obj json.RawMessage
	if err := dec.Decode(&obj); err != nil || len(obj) == 0 || obj[0] != '{' {
		return nil, errAnswer
	}
	if t, err := dec.Token(); err != nil || t != json.Delim('}') {
		return nil, errAnswer
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errAnswer
	}
	return obj, nil
}

// fields decodes {"data": {...}} whose members are strings.
func fields(raw []byte, required []string, optional ...string) (map[string]string, error) {
	obj, err := data(raw)
	if err != nil {
		return nil, err
	}
	return devicecall.StrictStrings(obj, required, optional...)
}

// codes is a pair/request answer.
type codes struct {
	user, device, keyID string
	expires             time.Time
}

func parseCodes(raw []byte, now time.Time) (codes, error) {
	m, err := fields(raw, []string{"user_code", "device_code", "expires_at", "key_id"}, "poll_url")
	if err != nil {
		return codes{}, err
	}
	exp, err := time.Parse(time.RFC3339Nano, m["expires_at"])
	if err != nil || !userCodeRe.MatchString(m["user_code"]) || !deviceCodeRe.MatchString(m["device_code"]) {
		return codes{}, errAnswer
	}
	if !exp.After(now) {
		return codes{}, errAnswer
	}
	if exp.After(now.Add(maxCodeLife)) {
		exp = now.Add(maxCodeLife)
	}
	return codes{user: m["user_code"], device: m["device_code"], keyID: m["key_id"], expires: exp}, nil
}

// deviceCodeOf reads data.device_code from an answer that failed the
// strict parse, so its code can still be cancelled; "" when absent.
func deviceCodeOf(raw []byte) string {
	var doc struct {
		Data struct {
			DeviceCode string `json:"device_code"`
		} `json:"data"`
	}
	if len(raw) > devicecall.MaxAnswer || json.Unmarshal(raw, &doc) != nil || !deviceCodeRe.MatchString(doc.Data.DeviceCode) {
		return ""
	}
	return doc.Data.DeviceCode
}

// pairing is a pair/complete answer.
type pairing struct {
	serverID, serverName, userID, deviceID, keyID string
}

func parsePairing(raw []byte) (pairing, error) {
	m, err := fields(raw, []string{"server_id", "device_id", "key_id"}, "server_name", "user_id")
	if err != nil {
		return pairing{}, err
	}
	p := pairing{serverID: m["server_id"], deviceID: m["device_id"], keyID: m["key_id"], userID: m["user_id"]}
	if !claims.ValidUUID(p.serverID) || !claims.ValidUUID(p.deviceID) || (p.userID != "" && !claims.ValidUUID(p.userID)) {
		return pairing{}, errAnswer
	}
	if n, err := cleanName(m["server_name"]); err == nil && strings.TrimSpace(m["server_name"]) != "" {
		p.serverName = n
	}
	return p, nil
}

// cleanName trims the server name and refuses one the server would refuse.
func cleanName(s string) (string, error) {
	s = strings.TrimSpace(s)
	if !utf8.ValidString(s) || utf8.RuneCountInString(s) > maxName || strings.ContainsFunc(s, unicode.IsControl) {
		return "", ErrInvalidName
	}
	if s == "" {
		return defaultName, nil
	}
	return s, nil
}

// requestError explains a refused pair/request.
func requestError(a devicecall.Answer) *Error {
	r := devicecall.ParseRefusal(a.Body)
	if a.Status == http.StatusTooManyRequests {
		return &Error{Text: "Too many pairing requests from this network. Try again in a few minutes."}
	}
	if a.Status == http.StatusServiceUnavailable {
		return &Error{Text: "Pairing is paused or Seawise.io is unavailable. Try again in a few minutes."}
	}
	if a.Status == http.StatusBadRequest && r.Error == "invalid_key" {
		return &Error{Text: "Seawise.io refused this device key. Start pairing again."}
	}
	if a.Status == http.StatusBadRequest {
		return &Error{Text: "Seawise.io refused the server name."}
	}
	if a.Status == http.StatusUnauthorized {
		return &Error{Text: "Seawise.io refused the request signature (" + devicecall.SafeCode(r.Code) + "). Try again."}
	}
	return &Error{Text: "Could not start pairing (status " + strconv.Itoa(a.Status) + ")."}
}
