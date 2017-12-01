package config

import (
	"flag"
	"time"
)

type Config struct {
	Discard bool
	Host    string
	Timeout time.Duration
}

func NewConfig() *Config {

	config := new(Config)

	var rejectAction string

	flag.StringVar(&config.Host, "host", "localhost:11333", "Rspamd host to connect")
	flag.StringVar(&rejectAction, "reject-action", "add_header", "Reject action: add_header or discard")
	flag.DurationVar(&config.Timeout, "timeout", 15, "Rspamd request timeout in seconds")

	flag.Parse()

	if rejectAction == "discard" {
		config.Discard = true
	}

	config.Timeout *= time.Second

	return config
}
