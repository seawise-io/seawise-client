package server

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/seawise/client/internal/api"
	"github.com/seawise/client/internal/config"
)

// ErrDuplicateServiceName is returned when the caller tries to add a
// service with a name that is already present in machine.json.
var ErrDuplicateServiceName = errors.New("service with that name already exists locally")

// addLocalService appends a new service to machine.json. It does not call
// the API. Returns the stored LocalService (populated with a fresh LocalID).
func addLocalService(name, host string, port int, iconURL string) (*config.LocalService, error) {
	m, err := config.LoadMachine()
	if err != nil {
		return nil, fmt.Errorf("load machine: %w", err)
	}

	for _, existing := range m.Services {
		if strings.EqualFold(existing.Name, name) {
			return nil, ErrDuplicateServiceName
		}
	}

	localID, err := config.GenerateLocalID()
	if err != nil {
		return nil, fmt.Errorf("generate local id: %w", err)
	}

	svc := config.LocalService{
		LocalID: localID,
		Name:    name,
		Host:    host,
		Port:    port,
		IconURL: iconURL,
	}
	m.Services = append(m.Services, svc)
	if err := m.Save(); err != nil {
		return nil, fmt.Errorf("save machine: %w", err)
	}
	return &svc, nil
}

// recordServerRegistration updates the machine.json entry matching localID
// with the server-assigned ID and subdomain.
func recordServerRegistration(localID, serverServiceID, subdomain string) error {
	m, err := config.LoadMachine()
	if err != nil {
		return fmt.Errorf("load machine: %w", err)
	}
	for i := range m.Services {
		if m.Services[i].LocalID == localID {
			m.Services[i].ServerServiceID = serverServiceID
			m.Services[i].Subdomain = subdomain
			return m.Save()
		}
	}
	return fmt.Errorf("service with local id %q not found", localID)
}

// removeLocalServiceByLocalID deletes a machine.json entry by LocalID.
// Returns the removed entry so the caller can use its ServerServiceID to
// call the API delete endpoint. Returns nil if the service was not found.
func removeLocalServiceByLocalID(localID string) (*config.LocalService, error) {
	m, err := config.LoadMachine()
	if err != nil {
		return nil, fmt.Errorf("load machine: %w", err)
	}
	for i := range m.Services {
		if m.Services[i].LocalID == localID {
			removed := m.Services[i]
			m.Services = append(m.Services[:i], m.Services[i+1:]...)
			if err := m.Save(); err != nil {
				return nil, fmt.Errorf("save machine: %w", err)
			}
			return &removed, nil
		}
	}
	return nil, nil
}

// removeLocalServiceByServerID is the same as above but keyed by the
// server-assigned service ID. Used when the UI holds onto server IDs.
func removeLocalServiceByServerID(serverServiceID string) (*config.LocalService, error) {
	m, err := config.LoadMachine()
	if err != nil {
		return nil, fmt.Errorf("load machine: %w", err)
	}
	for i := range m.Services {
		if m.Services[i].ServerServiceID == serverServiceID {
			removed := m.Services[i]
			m.Services = append(m.Services[:i], m.Services[i+1:]...)
			if err := m.Save(); err != nil {
				return nil, fmt.Errorf("save machine: %w", err)
			}
			return &removed, nil
		}
	}
	return nil, nil
}

// registerLocalServices POSTs every service in machine.json that has no
// server_service_id to the API batch endpoint, then writes the returned
// IDs + subdomains back into machine.json.
//
// Called right after a successful pair and any time an unpaired-then-
// repaired machine has local services that need re-registering on the new
// account.
func registerLocalServices(apiClient *api.Client, serverID string) error {
	if apiClient == nil {
		return fmt.Errorf("nil api client")
	}

	m, err := config.LoadMachine()
	if err != nil {
		return fmt.Errorf("load machine: %w", err)
	}

	// Collect services that need registering.
	var toRegister []config.LocalService
	for _, svc := range m.Services {
		if svc.ServerServiceID == "" {
			toRegister = append(toRegister, svc)
		}
	}

	if len(toRegister) == 0 {
		return nil
	}

	inputs := make([]api.BatchServiceInput, 0, len(toRegister))
	for _, svc := range toRegister {
		inputs = append(inputs, api.BatchServiceInput{
			Name:    svc.Name,
			Host:    svc.Host,
			Port:    svc.Port,
			IconURL: svc.IconURL,
		})
	}

	results, err := apiClient.BatchRegisterServices(serverID, inputs)
	if err != nil {
		return fmt.Errorf("batch register: %w", err)
	}

	// Match results back to machine.json services by name. Names are unique
	// within a machine, enforced at add-time by the local UI.
	resultByName := make(map[string]api.BatchRegisterResult, len(results))
	for _, r := range results {
		resultByName[r.Name] = r
	}

	for i := range m.Services {
		if m.Services[i].ServerServiceID != "" {
			continue
		}
		r, ok := resultByName[m.Services[i].Name]
		if !ok {
			continue
		}
		m.Services[i].ServerServiceID = r.ID
		m.Services[i].Subdomain = r.Subdomain
	}

	if err := m.Save(); err != nil {
		return fmt.Errorf("save machine after batch: %w", err)
	}

	slog.Info("Batch-registered local services on server", "component", "service_sync", "count", len(results))
	return nil
}

// syncMachineServicesFromServer populates machine.json.services from the
// server if the machine has no local definitions but is currently paired.
//
// This covers the one-time bootstrap for clients upgraded from the
// pre-split config.json: they already have services living on the server,
// so the local machine.json needs to learn about them to survive future
// unpair/repair cycles.
func syncMachineServicesFromServer(apiClient *api.Client, serverID string) error {
	if apiClient == nil {
		return fmt.Errorf("nil api client")
	}

	m, err := config.LoadMachine()
	if err != nil {
		return fmt.Errorf("load machine: %w", err)
	}

	if len(m.Services) > 0 {
		// Already populated; nothing to do.
		return nil
	}

	serverServices, err := apiClient.ListServices(serverID)
	if err != nil {
		return fmt.Errorf("list services: %w", err)
	}

	if len(serverServices) == 0 {
		return nil
	}

	services := make([]config.LocalService, 0, len(serverServices))
	for _, s := range serverServices {
		localID, err := config.GenerateLocalID()
		if err != nil {
			return fmt.Errorf("generate local id: %w", err)
		}
		services = append(services, config.LocalService{
			LocalID:         localID,
			Name:            s.Name,
			Host:            s.Host,
			Port:            s.Port,
			ServerServiceID: s.ID,
			Subdomain:       s.Subdomain,
		})
	}

	m.Services = services
	if err := m.Save(); err != nil {
		return fmt.Errorf("save machine: %w", err)
	}

	slog.Info("Synced services from server into machine state", "component", "service_sync", "count", len(services))
	return nil
}
