//go:build linux

package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/seawise/client/internal/store"
)

type pidRecord struct {
	PID        int    `json:"pid"`
	StartTicks uint64 `json:"start_ticks"`
	Exe        string `json:"exe"`
}

// setPdeathsig makes the kernel kill frpc if the agent dies without
// stopping it.
func setPdeathsig(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
}

func (a *Agent) pidPath() string {
	return filepath.Join(a.cfg.Store.Dir(), PIDFile)
}

func (a *Agent) recordPID(pid int) error {
	ticks, err := procStartTicks(pid)
	if err != nil {
		return err
	}
	b, err := json.Marshal(pidRecord{PID: pid, StartTicks: ticks, Exe: a.cfg.FRPCPath})
	if err != nil {
		return err
	}
	if err := store.WriteFileAtomic(a.pidPath(), b, 0o600); err != nil && !errors.Is(err, store.ErrNotDurable) {
		return err
	}
	return nil
}

func (a *Agent) clearPID() {
	if err := os.Remove(a.pidPath()); err != nil && !errors.Is(err, fs.ErrNotExist) {
		a.log.Warn("remove frpc pid record", "error", err)
	}
}

// killStale stops an frpc left running by a previous agent, but only if the
// recorded pid still belongs to that same frpc process.
func (a *Agent) killStale() {
	info, err := os.Lstat(a.pidPath())
	if err != nil || !info.Mode().IsRegular() {
		return
	}
	defer a.clearPID()
	b, err := os.ReadFile(a.pidPath())
	if err != nil {
		return
	}
	var rec pidRecord
	if json.Unmarshal(b, &rec) != nil || rec.PID <= 1 {
		return
	}
	ticks, err := procStartTicks(rec.PID)
	if err != nil || ticks != rec.StartTicks {
		return
	}
	if !a.isOurFRPC(rec.PID) {
		a.log.Warn("recorded frpc pid now belongs to another program; leaving it alone", "pid", rec.PID)
		return
	}
	a.log.Warn("stopping frpc left by a previous agent", "pid", rec.PID)
	_ = syscall.Kill(rec.PID, syscall.SIGTERM)
	if waitGone(rec.PID, a.cfg.StopTimeout) {
		return
	}
	_ = syscall.Kill(rec.PID, syscall.SIGKILL)
	waitGone(rec.PID, time.Second)
}

func (a *Agent) isOurFRPC(pid int) bool {
	exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return false
	}
	want, err := filepath.EvalSymlinks(a.cfg.FRPCPath)
	if err != nil || strings.TrimSuffix(exe, " (deleted)") != want {
		return false
	}
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return false
	}
	args := strings.Split(strings.TrimSuffix(string(raw), "\x00"), "\x00")
	return len(args) == 3 && args[1] == "-c" && args[2] == a.ConfigPath()
}

func waitGone(pid int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		if !procAlive(pid) {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// procStat returns the fields of /proc/<pid>/stat after the command name.
func procStat(pid int) ([]string, error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return nil, err
	}
	s := string(b)
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return nil, errors.New("unexpected stat format")
	}
	f := strings.Fields(s[i+1:])
	if len(f) < 20 {
		return nil, errors.New("unexpected stat format")
	}
	return f, nil
}

func procStartTicks(pid int) (uint64, error) {
	f, err := procStat(pid)
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(f[19], 10, 64)
}

func procAlive(pid int) bool {
	f, err := procStat(pid)
	return err == nil && f[0] != "Z" && f[0] != "X"
}
