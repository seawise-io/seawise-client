package main

import (
	"crypto"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/seawise-io/seawise-client/tunnelwire/claims"

	"github.com/seawise/client/internal/agent"
	"github.com/seawise/client/internal/constants"
	"github.com/seawise/client/internal/identity"
	"github.com/seawise/client/internal/protocol"
	"github.com/seawise/client/internal/session"
	"github.com/seawise/client/internal/store"
	"github.com/seawise/client/internal/transport"
)

// defaultTunnelName is the regional pool the agent dials; the dialer
// accepts it only while the signed edge list names that region.
const defaultTunnelName = "tunnel-us-east.seawise.dev"

type tunnelSetup struct {
	log    *slog.Logger
	st     *store.Store
	keys   identity.Keystore
	keySet func() *protocol.KeySet
	// keySetHold names why no new session may be dialled, or "".
	keySetHold func() string
	name       string
	client     *http.Client
}

// runID identifies this process to the edge; a reconnect with the same
// run is a handover, never a clone.
var runID = func() [16]byte {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return b
}()

func notReady(why string) error { return fmt.Errorf("%w: %s", agent.ErrNotReady, why) }

// tunnelFactory builds the session manager once the server is paired, the
// device key exists and a verified key set is available.
func tunnelFactory(ts tunnelSetup) func() (agent.Tunnel, error) {
	return func() (agent.Tunnel, error) {
		acc := ts.st.State().Account
		switch {
		case acc == nil:
			return nil, notReady("not paired")
		case !claims.ValidUUID(acc.ServerID):
			return nil, notReady("the paired server has no v2 identity yet")
		case ts.keys == nil:
			return nil, notReady("device keystore unavailable")
		}
		if _, err := ts.keys.Current(); err != nil {
			if errors.Is(err, identity.ErrNoKey) {
				return nil, notReady("no device key yet")
			}
			return nil, err
		}
		if ts.keySet() == nil {
			return nil, notReady("waiting for the signed key set")
		}
		signer := func() crypto.Signer {
			k, err := ts.keys.Current()
			if err != nil {
				return nil
			}
			return k
		}
		keyID := func() string {
			k, err := ts.keys.Current()
			if err != nil {
				return ""
			}
			return k.KeyID()
		}
		serverID := acc.ServerID
		newDialer := func() (*transport.Dialer, error) {
			k, err := ts.keys.Current()
			if err != nil {
				return nil, &transport.Error{Kind: transport.Local, Reason: "device_key", Err: err}
			}
			return transport.New(transport.Config{
				Edges: func() *transport.EdgeList {
					l, _ := transport.NewEdgeList(ts.keySet())
					return l
				},
				Key: k, ServerID: serverID, RunID: runID, AgentVersion: constants.Version,
				KillSwitch: func() bool { return ts.st.State().HasHold(store.HoldKillSwitch) },
				KeySetHold: ts.keySetHold,
				DataDir:    ts.st.Dir(), Logger: ts.log,
			})
		}
		m, err := session.New(session.Config{
			Dial: session.FromTransport(newDialer), Name: ts.name, ServerID: serverID,
			KeyID: keyID, KeySet: ts.keySet,
			Heartbeat: &session.Heartbeat{Origin: apiURL(ts.st), Key: signer, Client: ts.client, Version: constants.Version},
			DataDir:   ts.st.Dir(),
			Pending: func() crypto.Signer {
				k, err := ts.keys.Pending()
				if err != nil {
					return nil
				}
				return k
			},
			CommitRotation: ts.keys.CommitRotation,
			Logger:         ts.log,
		})
		if err != nil {
			return nil, err
		}
		return m, nil
	}
}
