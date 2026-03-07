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

// Эти значения будут перезаписаны при сборке через -ldflags
var (
	Version   = "dev"
	Commit    = "none"
	BuildTime = "unknown"
)

type Operation struct {
	Description string
	Direction   Direction
	Discard     bool
	MirrorTo    []string
	NotifyRcpts bool
	NotifyTo    []string
}

type Config struct {
	AuthservId  string
	Host        string        `default:"localhost:11333"`
	Timeout     time.Duration `default:"15s"`
	NotifyFrom  string        `required:"true"`
	Actions     map[string]*Operation
	Symbols     map[string]*Operation
	debug       bool
	outbound    bool
	showVersion bool
}

var configInstance *Config

func Action(a string) (op *Operation, ok bool) {
	op, ok = configInstance.Actions[a]
	return
}

func AuthservId() string {
	return configInstance.AuthservId
}

func Debug() bool {
	return configInstance.debug
}

func GetVersion() string {
	return fmt.Sprintf("rspamd-cgp\n  version:  %s\n  commit:   %s\n  built:    %s\n",
		Version, Commit, BuildTime)
}

func Host() string {
	return configInstance.Host
}

func New(args []string) (*Config, error) {

	c := &Config{}

	fs := flag.NewFlagSet("rspamd-cgp", flag.ContinueOnError)

	dir, _ := filepath.Abs(filepath.Dir(os.Args[0]))

	var configfile string
	var configdump bool
	var configtest bool
	var err error

	fs.StringVar(&configfile, "config", dir+"/rspamd-cgp.yml", "Set configuration file")
	fs.BoolVar(&configdump, "configdump", false, "Perform configuration file dump")
	fs.BoolVar(&configtest, "configtest", false, "Perform configuration file test")
	fs.BoolVar(&c.debug, "debug", false, "Run in debug mode")
	fs.BoolVar(&c.outbound, "outbound", false, "Outbound message flow processing")
	fs.BoolVar(&c.showVersion, "version", false, "print version and exit")

	if err = fs.Parse(args); err != nil {
		return nil, err
	}

	err = configor.Load(c, configfile)
	if err != nil {
		return nil, err
	}

	if configdump {
		dumpConfig(c)
		if err = validateConfig(c); err != nil {
			fmt.Println("config:", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	if configtest {
		if err = validateConfig(c); err != nil {
			fmt.Println("config:", err)
			os.Exit(1)
		} else {
			fmt.Println("config: Syntax OK")
			os.Exit(0)
		}
	}

	if c.AuthservId == "" {
		if c.AuthservId, err = cgp.MainDomain(); err != nil {
			return nil, fmt.Errorf("can not detect Main Domain: %v", err)
		}
	}

	c.Host = "http://" + c.Host + "/checkv2"

	return c, nil
}

func NotifyFrom() string {
	return configInstance.NotifyFrom
}

func Outbound() bool {
	return configInstance.outbound
}

func SetGlobal(c *Config) {
	configInstance = c
}

func ShowVersion() bool {
	return configInstance.showVersion
}

func Symbols() map[string]*Operation {
	return configInstance.Symbols
}

func Timeout() time.Duration {
	return configInstance.Timeout
}
