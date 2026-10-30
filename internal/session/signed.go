package session

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"

	"github.com/seawise-io/seawise-client/tunnelwire/claims"
	pb "github.com/seawise-io/seawise-client/tunnelwire/tunnelpb"

	"github.com/seawise/client/internal/protocol"
	"github.com/seawise/client/internal/store"
)

// FlagsFile keeps the last accepted protocol flags document.
const FlagsFile = "tunnel-flags.json"

type flagsFile struct {
	Schema     int    `json:"schema"`
	Generation int64  `json:"generation"`
	Mode       string `json:"mode"`
	Flags      string `json:"flags"`
}

// storedFlags is the persisted generation and mode; none is generation 0
// and ON, since the kill switch is a positive signed statement.
type storedFlags struct {
	generation int64
	on         bool
	doc        string
}

func loadFlags(dir string) (storedFlags, error) {
	def := storedFlags{on: true}
	if dir == "" {
		return def, nil
	}
	b, err := store.ReadOwned(filepath.Join(dir, FlagsFile))
	if errors.Is(err, fs.ErrNotExist) {
		return def, nil
	}
	if err != nil {
		return def, err
	}
	var f flagsFile
	if err := json.Unmarshal(b, &f); err != nil {
		return def, fmt.Errorf("%s: malformed", FlagsFile)
	}
	if f.Schema != 1 || f.Generation < 1 || (f.Mode != "ON" && f.Mode != "OFF") {
		return def, fmt.Errorf("%s: invalid", FlagsFile)
	}
	return storedFlags{generation: f.Generation, on: f.Mode == "ON", doc: f.Flags}, nil
}

func saveFlags(dir string, gen int64, on bool, doc string) error {
	if dir == "" {
		return nil
	}
	b, _ := json.Marshal(flagsFile{Schema: 1, Generation: gen, Mode: modeName(on), Flags: doc})
	err := store.WriteFileAtomic(filepath.Join(dir, FlagsFile), b, 0o600)
	if errors.Is(err, store.ErrNotDurable) {
		return nil
	}
	return err
}

func modeName(on bool) string {
	if on {
		return "ON"
	}
	return "OFF"
}

// verifyFlags checks a flags document from either carrier and evaluates it
// for this server.
func verifyFlags(doc string, ks *protocol.KeySet, serverID []byte) (*claims.Flags, bool, error) {
	payload, _, err := protocol.VerifyKeyed(doc, protocol.TypFlags, protocol.RoleControl, protocol.MaxFlagsSize, ks)
	if err != nil {
		return nil, false, err
	}
	f, err := claims.ParseFlags(payload)
	if err != nil {
		return nil, false, err
	}
	return f, f.Mode(serverID) == pb.ProtocolMode_ON, nil
}

// verifyState checks a signed device state bound to this server, the
// current device key and the nonce just sent.
func verifyState(tok string, ks *protocol.KeySet, serverID, keyID, nonce string) (*claims.SignedState, error) {
	payload, _, err := protocol.VerifyKeyed(tok, protocol.TypState, protocol.RoleControl, protocol.MaxStateSize, ks)
	if err != nil {
		return nil, err
	}
	return claims.CheckSignedState(payload, serverID, keyID, nonce)
}

// verifyRouteSet checks an edge-signed RouteSet for the session.
func verifyRouteSet(rs *pb.RouteSet, ks *protocol.KeySet, serverID string, info ConnInfo, last int64) (*claims.RouteSet, error) {
	payload, signer, err := protocol.VerifyKeyed(rs.GetJws(), protocol.TypRouteSet, protocol.RoleEdge, protocol.MaxRouteSetSize, ks)
	if err != nil {
		return nil, err
	}
	return claims.CheckRouteSet(payload, claims.RouteSetExpect{EdgeID: info.EdgeID, Signer: signer, ServerID: serverID,
		SessionID: info.SessionID, LastVersion: last})
}

// recheckFlags verifies the stored document again against the current key
// set; it must give the stored generation and mode.
func recheckFlags(f storedFlags, ks *protocol.KeySet, serverID []byte) error {
	doc, on, err := verifyFlags(f.doc, ks, serverID)
	if err != nil {
		return err
	}
	if doc.Generation != f.generation || on != f.on {
		return fmt.Errorf("%s: does not match its document", FlagsFile)
	}
	return nil
}
