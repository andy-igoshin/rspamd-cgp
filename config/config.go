package config

import (
	"flag"
	"strings"
	"time"
)

type Config struct {
	AuthservId    string
	Debug         bool
	Host          string
	MirrorDiscard bool
	MirrorTo      []string
	Timeout       time.Duration
}

func New() *Config {

	config := new(Config)

	var mirrorTo string

	flag.StringVar(&config.AuthservId, "authserv-id", "", "Authentication Identifier (default CommuniGate Pro Main Domain)")
	flag.StringVar(&config.Host, "host", "localhost:11333", "Rspamd host to connect")
	flag.BoolVar(&config.MirrorDiscard, "mirror-discard", false, "Mirror then discard selected messages")
	flag.StringVar(&mirrorTo, "mirror-to", "", "Mirror selected messages to email")
	flag.DurationVar(&config.Timeout, "timeout", 15*time.Second, "Rspamd request timeout")
	flag.BoolVar(&config.Debug, "debug", false, "Export debug information (for developers)")

	flag.Parse()

	if len(mirrorTo) > 0 {
		config.MirrorTo = strings.Split(strings.ReplaceAll(mirrorTo, " ", ""), ",")
	}

	if config.MirrorDiscard && len(config.MirrorTo) == 0 {
		config.MirrorDiscard = false
	}

	if config.Timeout < time.Second {
		config.Timeout *= time.Second
	}

	return config
}
