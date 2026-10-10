//go:build !linux

package agent

import "os/exec"

func setPdeathsig(*exec.Cmd)         {}
func (a *Agent) recordPID(int) error { return nil }
func (a *Agent) clearPID()           {}
func (a *Agent) killStale()          {}
