package appsync

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"slices"
	"time"

	"github.com/seawise/client/internal/store"
)

const (
	// OutboxFile holds the outbox under the store directory.
	OutboxFile    = "appsync.json"
	fileSchema    = 1
	MaxCalls      = 64
	maxDeleted    = 1000
	maxRegistered = 2 * store.MaxTargets
	maxFile       = 16 << 20
)

// Call operations.
const (
	OpRegister = "register"
	OpDelete   = "delete"
)

// Call is a frozen register or delete call. Body is sent byte for byte on
// every attempt under Key.
type Call struct {
	Key       string    `json:"key"`
	Op        string    `json:"op"`
	Body      []byte    `json:"body"`
	LocalIDs  []string  `json:"local_ids"`
	Adopt     bool      `json:"adopt,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// File is the persistent outbox of one server.
type File struct {
	Schema   int    `json:"schema"`
	ServerID string `json:"server_id"`
	// Adopted is set once the first v2 sync registered every local app.
	Adopted bool   `json:"adopted"`
	Calls   []Call `json:"calls"`
	// Registered are local_ids the server confirmed; only these are deleted.
	Registered []string `json:"registered"`
	// Deleted are local_ids removed here or tombstoned by the server; they
	// are never registered again.
	Deleted []string `json:"deleted"`
	// Retired are 1.x apps removed here before the first v2 sync: they are
	// adopted with the other apps and then deleted.
	Retired []Retired `json:"retired,omitempty"`
}

// Retired is a removed 1.x app still to be adopted and deleted.
type Retired struct {
	LocalID  string `json:"local_id"`
	ServerID string `json:"server_id"`
	Name     string `json:"name"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	IconURL  string `json:"icon_url,omitempty"`
}

func emptyFile(serverID string) File {
	return File{Schema: fileSchema, ServerID: serverID, Calls: []Call{}, Registered: []string{}, Deleted: []string{}}
}

func (f *File) marshal() ([]byte, error) {
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// ParseFile reads an outbox file strictly: one object, no unknown members,
// every call consistent with its body.
func ParseFile(raw []byte) (File, error) {
	var f File
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return File{}, errors.New("outbox: malformed")
	}
	if _, err := dec.Token(); err != io.EOF {
		return File{}, errors.New("outbox: trailing data")
	}
	if err := f.check(); err != nil {
		return File{}, fmt.Errorf("outbox: %w", err)
	}
	return f, nil
}

func checkIDs(ids []string, max int) error {
	if ids == nil || len(ids) > max {
		return errors.New("id list missing or too long")
	}
	seen := map[string]bool{}
	for _, id := range ids {
		if !ValidLocalID(id) || seen[id] {
			return errors.New("bad or repeated local_id")
		}
		seen[id] = true
	}
	return nil
}

func (f *File) check() error {
	if f.Schema != fileSchema {
		return errors.New("unknown schema")
	}
	if f.ServerID != "" && !ValidLocalID(f.ServerID) {
		return errors.New("bad server_id")
	}
	if f.Calls == nil || len(f.Calls) > MaxCalls {
		return errors.New("calls missing or too many")
	}
	if err := checkIDs(f.Registered, maxRegistered); err != nil {
		return fmt.Errorf("registered: %w", err)
	}
	if err := checkIDs(f.Deleted, maxDeleted); err != nil {
		return fmt.Errorf("deleted: %w", err)
	}
	if len(f.Retired) > maxDeleted {
		return errors.New("too many retired apps")
	}
	retired := map[string]bool{}
	for i, r := range f.Retired {
		if !ValidLocalID(r.LocalID) || !ValidLocalID(r.ServerID) || retired[r.LocalID] || checkApp(r.Name, r.Host, r.Port, r.IconURL) != nil {
			return fmt.Errorf("retired %d: malformed or repeated", i)
		}
		retired[r.LocalID] = true
	}
	keys := map[string]bool{}
	for i, c := range f.Calls {
		if !keyRe.MatchString(c.Key) || keys[c.Key] {
			return fmt.Errorf("call %d: bad or repeated key", i)
		}
		keys[c.Key] = true
		if len(c.Body) > MaxBody {
			return fmt.Errorf("call %d: body too large", i)
		}
		ids, err := bodyIDs(c.Op, c.Body)
		if err != nil {
			return fmt.Errorf("call %d: %w", i, err)
		}
		if !slices.Equal(ids, c.LocalIDs) || checkIDs(c.LocalIDs, MaxItems) != nil || len(ids) == 0 {
			return fmt.Errorf("call %d: local_ids do not match the body", i)
		}
		if c.Adopt && c.Op != OpRegister {
			return fmt.Errorf("call %d: adoption is a register", i)
		}
	}
	return nil
}

// bodyIDs returns the local_ids a call body names, in order.
func bodyIDs(op string, body []byte) ([]string, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	var ids []string
	switch op {
	case OpRegister:
		var b registerBody
		if err := dec.Decode(&b); err != nil {
			return nil, errors.New("malformed register body")
		}
		for _, a := range b.Apps {
			ids = append(ids, a.LocalID)
		}
	case OpDelete:
		var b deleteBody
		if err := dec.Decode(&b); err != nil {
			return nil, errors.New("malformed delete body")
		}
		ids = b.LocalIDs
	default:
		return nil, errors.New("unknown op")
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("trailing data in body")
	}
	return ids, nil
}

func loadFile(path string) (File, bool, error) {
	raw, err := store.ReadOwned(path)
	if errors.Is(err, fs.ErrNotExist) {
		return File{}, false, nil
	}
	if err != nil {
		return File{}, false, err
	}
	if len(raw) > maxFile {
		return File{}, false, errors.New("outbox: file too large")
	}
	f, err := ParseFile(raw)
	return f, true, err
}

func saveFile(path string, f *File) error {
	if err := f.check(); err != nil {
		return fmt.Errorf("outbox: %w", err)
	}
	b, err := f.marshal()
	if err != nil {
		return err
	}
	err = store.WriteFileAtomic(path, b, 0o600)
	if errors.Is(err, store.ErrNotDurable) {
		return nil
	}
	return err
}

// addID appends id to list, dropping the oldest entries beyond max.
func addID(list []string, id string, max int) []string {
	if slices.Contains(list, id) {
		return list
	}
	list = append(list, id)
	if len(list) > max {
		list = slices.Clone(list[len(list)-max:])
	}
	return list
}

func removeID(list []string, id string) []string {
	return slices.DeleteFunc(list, func(s string) bool { return s == id })
}
