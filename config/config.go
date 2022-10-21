package config

import (
	"flag"
	"math"
	"strings"
	"time"
)

type Config struct {
	AuthservId  string
	Debug       bool
	Host        string
	MirrorTo    []string
	RejectScore float64
	Timeout     time.Duration
}

func New() *Config {

	config := new(Config)

	var mirrorTo string

	flag.StringVar(&config.AuthservId, "authserv-id", "", "Authentication Identifier (default CommuniGate Pro Main Domain)")
	flag.StringVar(&config.Host, "host", "localhost:11333", "Rspamd host to connect")
	flag.StringVar(&mirrorTo, "mirror-to", "", "Mirror selected messages to email")
	flag.Float64Var(&config.RejectScore, "reject-score", math.Inf(1), "Reject score to discard")
	flag.DurationVar(&config.Timeout, "timeout", 15*time.Second, "Rspamd request timeout")
	flag.BoolVar(&config.Debug, "debug", false, "Export debug information (for developers)")

	flag.Parse()

	if len(mirrorTo) > 0 {
		config.MirrorTo = strings.Split(strings.ReplaceAll(mirrorTo, " ", ""), ",")
	}

	if config.Timeout < time.Second {
		config.Timeout *= time.Second
	}

	return config
}
