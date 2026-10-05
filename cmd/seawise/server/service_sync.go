package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/seawise/client/internal/api"
	"github.com/seawise/client/internal/config"
	"github.com/seawise/client/internal/frp"
)

var ErrDuplicateServiceName = errors.New("service with that name already exists locally")

func addLocalService(name, host string, port int, iconURL string) (*config.LocalService, error) {
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
	err = config.UpdateMachine(func(m *config.Machine) error {
		for _, existing := range m.Services {
			if strings.EqualFold(existing.Name, name) {
				return ErrDuplicateServiceName
			}
		}
		m.Services = append(m.Services, svc)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &svc, nil
}

func recordServerRegistration(localID, serverServiceID, subdomain string) error {
	return config.UpdateMachine(func(m *config.Machine) error {
		for i := range m.Services {
			if m.Services[i].LocalID == localID {
				m.Services[i].ServerServiceID = serverServiceID
				m.Services[i].Subdomain = subdomain
				return nil
			}
		}
		return fmt.Errorf("service with local id %q not found", localID)
	})
}

func removeLocalService(match func(config.LocalService) bool) (*config.LocalService, error) {
	var removed *config.LocalService
	err := config.UpdateMachine(func(m *config.Machine) error {
		for i := range m.Services {
			if match(m.Services[i]) {
				r := m.Services[i]
				removed = &r
				m.Services = append(m.Services[:i], m.Services[i+1:]...)
				return nil
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return removed, nil
}

func removeLocalServiceByLocalID(localID string) (*config.LocalService, error) {
	return removeLocalService(func(s config.LocalService) bool { return s.LocalID == localID })
}

func removeLocalServiceByServerID(serverServiceID string) (*config.LocalService, error) {
	return removeLocalService(func(s config.LocalService) bool { return s.ServerServiceID == serverServiceID })
}

func setLocalServiceDisabled(localID string, disabled bool) (*config.LocalService, error) {
	var updated *config.LocalService
	err := config.UpdateMachine(func(m *config.Machine) error {
		for i := range m.Services {
			if m.Services[i].LocalID == localID {
				m.Services[i].Disabled = disabled
				if disabled {
					m.Services[i].ServerServiceID = ""
					m.Services[i].Subdomain = ""
				}
				u := m.Services[i]
				updated = &u
				return nil
			}
		}
		return nil
	})
	return updated, err
}

func clearServerRegistrations() error {
	return config.UpdateMachine(func(m *config.Machine) error {
		for i := range m.Services {
			m.Services[i].ServerServiceID = ""
			m.Services[i].Subdomain = ""
		}
		return nil
	})
}

func registerLocalServices(ctx context.Context, apiClient *api.Client, serverID string) error {
	if apiClient == nil {
		return fmt.Errorf("nil api client")
	}

	m, err := config.LoadMachine()
	if err != nil {
		return fmt.Errorf("load machine: %w", err)
	}

	var toRegister []config.LocalService
	for _, svc := range m.Services {
		if svc.ServerServiceID == "" && !svc.Disabled {
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

	results, err := apiClient.BatchRegisterServices(ctx, serverID, inputs)
	if err != nil {
		return fmt.Errorf("batch register: %w", err)
	}

	resultByName := make(map[string]api.BatchRegisterResult, len(results))
	for _, r := range results {
		key := r.RequestedName
		if key == "" {
			key = r.Name
		}
		resultByName[key] = r
	}

	sent := make(map[string]bool, len(toRegister))
	for _, svc := range toRegister {
		sent[svc.LocalID] = true
	}

	recorded := 0
	err = config.UpdateMachine(func(m *config.Machine) error {
		for i := range m.Services {
			ls := &m.Services[i]
			if !sent[ls.LocalID] || ls.ServerServiceID != "" || ls.Disabled {
				continue
			}
			r, ok := resultByName[ls.Name]
			if !ok {
				continue
			}
			ls.ServerServiceID = r.ID
			ls.Subdomain = r.Subdomain
			recorded++
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("save machine after batch: %w", err)
	}

	slog.Info("Registered local services on server", "component", "service_sync", "count", recorded)
	return nil
}

func reconcileMachineServicesWithServer(ctx context.Context, apiClient *api.Client, serverID string) (bool, error) {
	if apiClient == nil {
		return false, fmt.Errorf("nil api client")
	}

	if err := registerLocalServices(ctx, apiClient, serverID); err != nil {
		slog.Warn("Retry of local-only services failed", "component", "service_sync", "error", err)
	}

	serverServices, err := apiClient.ListServices(ctx, serverID)
	if err != nil {
		return false, fmt.Errorf("list services: %w", err)
	}
	onServer := make(map[string]bool, len(serverServices))
	for _, s := range serverServices {
		onServer[s.ID] = true
	}

	var disabled []string
	err = config.UpdateMachine(func(m *config.Machine) error {
		for i := range m.Services {
			ls := &m.Services[i]
			if ls.ServerServiceID == "" || onServer[ls.ServerServiceID] {
				continue
			}
			ls.Disabled = true
			ls.ServerServiceID = ""
			ls.Subdomain = ""
			disabled = append(disabled, ls.Name)
		}
		return nil
	})
	if err != nil {
		return false, fmt.Errorf("save machine: %w", err)
	}

	if len(disabled) > 0 {
		slog.Info("Disabled services removed from account", "component", "service_sync", "count", len(disabled), "names", disabled)
	}
	return len(disabled) > 0, nil
}

func buildTunnelServices(m *config.Machine, apiServices []api.Service) []frp.Service {
	onServer := make(map[string]bool, len(apiServices))
	for _, s := range apiServices {
		onServer[s.ID] = true
	}
	out := make([]frp.Service, 0, len(m.Services))
	for _, ls := range m.Services {
		if ls.Disabled || ls.ServerServiceID == "" || !onServer[ls.ServerServiceID] {
			continue
		}
		if ls.Subdomain == "" {
			slog.Warn("Skipping registered service without subdomain", "component", "service_sync", "name", ls.Name)
			continue
		}
		out = append(out, frp.Service{
			Name:      ls.Name,
			LocalIP:   ls.Host,
			LocalPort: ls.Port,
			Subdomain: ls.Subdomain,
		})
	}
	return out
}
