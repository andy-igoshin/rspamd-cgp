package config

import (
	"flag"
	"time"
)

type Config struct {
	AuthservId string
	Discard    bool
	Host       string
	Timeout    time.Duration
}

func New() *Config {

	config := new(Config)

	var rejectAction string

	flag.StringVar(&config.AuthservId, "authserv-id", "", "Authentication Identifier (default CommuniGate Pro Main Domain)")
	flag.StringVar(&config.Host, "host", "localhost:11333", "Rspamd host to connect")
	flag.StringVar(&rejectAction, "reject-action", "add_header", "Reject action: \"add_header\" or \"discard\"")
	flag.DurationVar(&config.Timeout, "timeout", 15*time.Second, "Rspamd request timeout")

	flag.Parse()

	if rejectAction == "discard" {
		config.Discard = true
	}

	if config.Timeout < time.Second {
		config.Timeout *= time.Second
	}

	return config
}
