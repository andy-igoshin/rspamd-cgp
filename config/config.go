package config

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/jinzhu/configor"

	"git.vsu.ru/ai/rspamd-cgp/cgp"
)

type Operation struct {
	Description string
	Direction   string
	Discard     bool
	MirrorTo    []string
	NotifyRcpts bool
	NotifyTo    []string
}

type Config struct {
	AuthservId string
	Debug      bool
	Outbound   bool
	Host       string        `default:"localhost:11333"`
	Timeout    time.Duration `default:"15s"`
	NotifyFrom string        `required:"true"`
	Actions    map[string]*Operation
	Symbols    map[string]*Operation
}

func New() *Config {

	config := new(Config)

	dir, _ := filepath.Abs(filepath.Dir(os.Args[0]))

	var configfile string
	var configdump bool
	var configtest bool
	var debug bool
	var outbound bool

	flag.StringVar(&configfile, "config", dir+"/rspamd-cgp.yml", "Set configuration file")
	flag.BoolVar(&configdump, "configdump", false, "Perform configuration file dump")
	flag.BoolVar(&configtest, "configtest", false, "Perform configuration file test")
	flag.BoolVar(&debug, "debug", false, "Run in debug mode")
	flag.BoolVar(&outbound, "outbound", false, "Outbound message flow processing")
	flag.Parse()

	err := configor.Load(config, configfile)
	if err != nil {
		fmt.Println("config:", err)
		os.Exit(1)
	}

	if debug {
		config.Debug = debug
	}

	if outbound {
		config.Outbound = outbound
	}

	if configdump {
		dumpConfig(config)
		if err = validateConfig(config); err != nil {
			fmt.Println("config:", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	if configtest {
		if err = validateConfig(config); err != nil {
			fmt.Println("config:", err)
			os.Exit(1)
		} else {
			fmt.Println("config: Syntax OK")
			os.Exit(0)
		}
	}

	if config.AuthservId == "" {
		if config.AuthservId, err = cgp.MainDomain(); err != nil {
			fmt.Println("Can not detect Main Domain:", err)
			os.Exit(1)
		}
	}

	setOpDefaultDirection(config)

	config.Host = "http://" + config.Host + "/checkv2"

	return config
}
