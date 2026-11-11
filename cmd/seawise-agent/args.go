package main

import (
	"errors"
	"log/slog"
	"strconv"
	"strings"
)

// options are the command line: the 1.x form "[serve] [--port N | -p N]"
// keeps existing docker run commands and templates working.
type options struct {
	help bool
	port int // 0 when not given
}

func parseArgs(args []string) (options, error) {
	var o options
	if len(args) > 0 && args[0] == "serve" {
		args = args[1:]
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-h" || a == "--help" || a == "help":
			o.help = true
		case a == "-p" || a == "--port":
			if i+1 >= len(args) {
				return o, errors.New(a + " needs a port")
			}
			i++
			if err := o.setPort(args[i]); err != nil {
				return o, err
			}
		case strings.HasPrefix(a, "--port="):
			if err := o.setPort(strings.TrimPrefix(a, "--port=")); err != nil {
				return o, err
			}
		case strings.HasPrefix(a, "-p") && len(a) > 2:
			if err := o.setPort(strings.TrimPrefix(strings.TrimPrefix(a, "-p"), "=")); err != nil {
				return o, err
			}
		default:
			return o, errors.New("unknown argument " + strconv.Quote(a))
		}
	}
	return o, nil
}

func (o *options) setPort(v string) error {
	p, err := strconv.Atoi(v)
	if err != nil || p < 1 || p > 65535 {
		return errors.New("invalid port " + strconv.Quote(v))
	}
	o.port = p
	return nil
}

// adminPort is the flag, else SEAWISE_PORT, else the default.
func adminPort(flag int, env string, def int) (int, error) {
	if flag != 0 {
		return flag, nil
	}
	if env == "" {
		return def, nil
	}
	p, err := strconv.Atoi(env)
	if err != nil || p < 1 || p > 65535 {
		return 0, errors.New("invalid SEAWISE_PORT")
	}
	return p, nil
}

// logLevel reads SEAWISE_LOG_LEVEL as 1.x did; anything else is info.
func logLevel(v string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
