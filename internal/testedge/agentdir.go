package testedge

import (
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/seawise/client/internal/identity"
	"github.com/seawise/client/internal/store"
)

// TestApps returns n apps for serverID's account whose targets are
// host:port.
func TestApps(n int, host string, port int) []App {
	apps := make([]App, 0, n)
	for i := 1; i <= n; i++ {
		apps = append(apps, App{ID: fmt.Sprintf("aaaaaaaa-0000-4000-8000-%012d", i), LocalID: fmt.Sprintf("bbbbbbbb-0000-4000-8000-%012d", i),
			Name: fmt.Sprintf("app %d", i), Host: host, Port: port, Subdomain: fmt.Sprintf("app%d-budget", i)})
	}
	return apps
}

// PairedDataDir makes dir the data folder of an agent paired with a
// device key to serverID, with apps already registered, and returns the
// device's public key.
func PairedDataDir(dir, serverID, apiURL string, apps []App) (ed25519.PublicKey, error) {
	st, err := store.Open(dir, time.Now)
	if err != nil {
		return nil, err
	}
	defer st.Close()
	ks, err := identity.Open(identity.BackendFile, st.Dir(), time.Now)
	if err != nil {
		return nil, err
	}
	defer ks.Close()
	k, err := ks.Create()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	err = st.Update(func(s *store.State) error {
		s.Account = &store.Account{ServerID: serverID, ServerName: "budget", APIURL: apiURL,
			DeviceID: serverID, KeyID: k.KeyID()}
		for _, a := range apps {
			s.Targets = append(s.Targets, store.Target{LocalID: a.LocalID, Name: a.Name, Host: a.Host, Port: a.Port,
				ServerServiceID: a.ID, Subdomain: a.Subdomain, Source: store.SourceLocal, ConfirmedAt: &now})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return k.PublicKey(), nil
}
