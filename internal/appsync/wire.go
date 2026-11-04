package appsync

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"unicode"
	"unicode/utf8"

	"github.com/seawise/client/internal/controlplane"
)

const (
	// MaxItems bounds the apps of one register and the ids of one delete.
	MaxItems = 50
	// MaxBody is the largest request a relayed call can carry.
	MaxBody     = 57344
	maxListApps = 1000
	maxListDel  = 1000
	maxName     = 100
	maxHost     = 255
	maxIcon     = 500
)

// Register results.
const (
	resCreated   = "created"
	resUpdated   = "updated"
	resUnchanged = "unchanged"
	resDeleted   = "deleted"
	resAbsent    = "absent"
	// resAbsentUnrecorded is absent without a tombstone on the server.
	resAbsentUnrecorded = "absent_unrecorded"
)

var hostRe = regexp.MustCompile(`^[A-Za-z0-9.:\[\]-]{1,255}$`)

// RegisterItem is one app of a register call.
type RegisterItem struct {
	LocalID     string `json:"local_id"`
	Name        string `json:"name"`
	Host        string `json:"host"`
	Port        int    `json:"port"`
	IconURL     string `json:"icon_url,omitempty"`
	PublicLocal bool   `json:"public_local"`
}

type registerBody struct {
	Apps []RegisterItem `json:"apps"`
}

type deleteBody struct {
	LocalIDs []string `json:"local_ids"`
}

type healthItem struct {
	LocalID string `json:"local_id"`
	Status  string `json:"status"`
}

type healthBody struct {
	Apps []healthItem `json:"apps"`
}

// checkApp applies the server's grammar for an app, so one bad app never
// makes a whole batch fail.
func checkApp(name, host string, port int, icon string) error {
	switch {
	case name == "" || utf8.RuneCountInString(name) > maxName || !utf8.ValidString(name):
		return errors.New("name must be 1-100 characters")
	case !hostRe.MatchString(host):
		return errors.New("invalid host")
	case port < 1 || port > 65535:
		return errors.New("port must be 1-65535")
	case len(icon) > maxIcon:
		return errors.New("icon URL too long")
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return errors.New("name has control characters")
		}
	}
	for i := 0; i < len(icon); i++ {
		if icon[i] < 0x20 || icon[i] > 0x7e {
			return errors.New("icon URL must be printable ASCII")
		}
	}
	return nil
}

// decodeStrict decodes exactly one JSON value.
func decodeStrict(raw []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(v); err != nil {
		return errors.New("malformed JSON")
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing data")
	}
	return nil
}

// RegisterResult is the server's answer for one register item.
type RegisterResult struct {
	LocalID   string
	ID        string
	Result    string
	Subdomain string
}

func parseRegisterAnswer(raw []byte, sent []string) ([]RegisterResult, error) {
	var doc struct {
		Items *[]struct {
			LocalID   *string `json:"local_id"`
			ID        *string `json:"id"`
			Result    *string `json:"result"`
			Subdomain *string `json:"subdomain"`
		} `json:"items"`
	}
	if err := decodeStrict(raw, &doc); err != nil {
		return nil, fmt.Errorf("register answer: %w", err)
	}
	if doc.Items == nil || len(*doc.Items) != len(sent) {
		return nil, errors.New("register answer: items do not match the request")
	}
	out := make([]RegisterResult, len(sent))
	for i, it := range *doc.Items {
		if it.LocalID == nil || *it.LocalID != sent[i] || it.Result == nil {
			return nil, fmt.Errorf("register answer: item %d does not match the request", i)
		}
		r := RegisterResult{LocalID: sent[i], Result: *it.Result}
		switch r.Result {
		case resDeleted:
			if it.ID != nil || it.Subdomain != nil {
				return nil, fmt.Errorf("register answer: item %d deleted with an id", i)
			}
		case resCreated, resUpdated, resUnchanged:
			if it.ID == nil || !ValidLocalID(*it.ID) || it.Subdomain == nil || !controlplane.ValidSubdomain(*it.Subdomain) {
				return nil, fmt.Errorf("register answer: item %d has no valid id or subdomain", i)
			}
			r.ID, r.Subdomain = *it.ID, *it.Subdomain
		default:
			return nil, fmt.Errorf("register answer: item %d has an unknown result", i)
		}
		out[i] = r
	}
	return out, nil
}

// parseDeleteAnswer checks a delete answer and returns the ids the server
// reported gone without recording a tombstone.
func parseDeleteAnswer(raw []byte, sent []string) ([]string, error) {
	var doc struct {
		Results *[]struct {
			LocalID *string `json:"local_id"`
			Result  *string `json:"result"`
		} `json:"results"`
	}
	if err := decodeStrict(raw, &doc); err != nil {
		return nil, fmt.Errorf("delete answer: %w", err)
	}
	if doc.Results == nil || len(*doc.Results) != len(sent) {
		return nil, errors.New("delete answer: results do not match the request")
	}
	var unrecorded []string
	for i, r := range *doc.Results {
		if r.LocalID == nil || *r.LocalID != sent[i] || r.Result == nil {
			return nil, fmt.Errorf("delete answer: result %d does not match the request", i)
		}
		switch *r.Result {
		case resDeleted, resAbsent:
		case resAbsentUnrecorded:
			unrecorded = append(unrecorded, sent[i])
		default:
			return nil, fmt.Errorf("delete answer: result %d does not match the request", i)
		}
	}
	return unrecorded, nil
}

// ServerApp is one live app in a list answer.
type ServerApp struct {
	ID              string
	LocalID         string // "" when not linked to any machine
	Name            string
	Host            string
	Port            int
	Subdomain       string
	PublicRequested bool
}

type listAnswer struct {
	Apps    []ServerApp
	Deleted []string
}

func parseList(raw []byte) (listAnswer, error) {
	var doc struct {
		Apps *[]struct {
			ID              *string `json:"id"`
			LocalID         *string `json:"local_id"`
			Name            *string `json:"name"`
			Host            *string `json:"host"`
			Port            *int    `json:"port"`
			Subdomain       *string `json:"subdomain"`
			PublicRequested *bool   `json:"public_requested"`
		} `json:"apps"`
		Deleted *[]string `json:"deleted"`
	}
	if err := decodeStrict(raw, &doc); err != nil {
		return listAnswer{}, fmt.Errorf("app list: %w", err)
	}
	if doc.Apps == nil || doc.Deleted == nil || len(*doc.Apps) > maxListApps || len(*doc.Deleted) > maxListDel {
		return listAnswer{}, errors.New("app list: apps and deleted must be bounded arrays")
	}
	out := listAnswer{Apps: make([]ServerApp, 0, len(*doc.Apps)), Deleted: make([]string, 0, len(*doc.Deleted))}
	seen := map[string]bool{}
	for i, a := range *doc.Apps {
		if a.ID == nil || !ValidLocalID(*a.ID) || a.Name == nil || len(*a.Name) > 4*maxName || a.Host == nil || len(*a.Host) > maxHost ||
			a.Port == nil || *a.Port < 1 || *a.Port > 65535 || a.Subdomain == nil || !controlplane.ValidSubdomain(*a.Subdomain) {
			return listAnswer{}, fmt.Errorf("app list: app %d is malformed", i)
		}
		s := ServerApp{ID: *a.ID, Name: *a.Name, Host: *a.Host, Port: *a.Port, Subdomain: *a.Subdomain}
		if a.LocalID != nil {
			if !ValidLocalID(*a.LocalID) || seen[*a.LocalID] {
				return listAnswer{}, fmt.Errorf("app list: app %d has a bad local_id", i)
			}
			seen[*a.LocalID] = true
			s.LocalID = *a.LocalID
		}
		if a.PublicRequested != nil {
			s.PublicRequested = *a.PublicRequested
		}
		out.Apps = append(out.Apps, s)
	}
	for _, d := range *doc.Deleted {
		if !ValidLocalID(d) {
			return listAnswer{}, errors.New("app list: bad deleted local_id")
		}
		out.Deleted = append(out.Deleted, d)
	}
	return out, nil
}

// errorBody is the error document of a refused call; every field is
// optional.
type errorBody struct {
	Error   string `json:"error"`
	Code    string `json:"code"`
	Index   *int   `json:"index"`
	LocalID string `json:"local_id"`
}

func parseError(raw []byte) errorBody {
	var e errorBody
	if json.Unmarshal(raw, &e) != nil {
		return errorBody{}
	}
	if len(e.Error) > 64 || len(e.Code) > 64 || (e.LocalID != "" && !ValidLocalID(e.LocalID)) {
		return errorBody{}
	}
	return e
}
