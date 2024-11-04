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
	Discard    bool
	MirrorTo   []string
	NotifySelf bool
	NotifyTo   []string
}

type Config struct {
	AuthservId string
	Debug      bool
	Host       string        `default:"localhost:11333"`
	Timeout    time.Duration `default:"15s"`
	Actions    map[string]Operation
	Symbols    map[string]Operation
}

func New() *Config {

	config := new(Config)

	dir, _ := filepath.Abs(filepath.Dir(os.Args[0]))

	var configfile string
	var configdump bool
	var configtest bool

	flag.StringVar(&configfile, "config", dir+"/rspamd-cgp.yml", "Set configuration file")
	flag.BoolVar(&configdump, "configdump", false, "Perform configuration file dump")
	flag.BoolVar(&configtest, "configtest", false, "Perform configuration file test")
	flag.Parse()

	err := configor.Load(config, configfile)
	if err != nil {
		fmt.Println("config:", err)
		os.Exit(1)
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

	config.Host = "http://" + config.Host + "/checkv2"

	return config
}
