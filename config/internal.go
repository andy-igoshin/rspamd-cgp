package config

import (
	"fmt"
	"regexp"

	"gopkg.in/yaml.v3"
)

var reMail *regexp.Regexp

func dumpConfig(config *Config) {
	yml, err := yaml.Marshal(config)
	if err != nil {
		fmt.Println("config:", err)
	} else {
		fmt.Println(string(yml))
	}
}

func validateConfig(config *Config) (err error) {

	reMail = regexp.MustCompile(`^\S+?@\S+$`)

	if err = validateConfigEntry(config.Actions); err != nil {
		return
	}

	if err = validateConfigEntry(config.Symbols); err != nil {
		return
	}

	return
}

func validateConfigEntry(entry map[string]Operations) (err error) {

	for e, op := range entry {

		if err = validateConfigOp(op.NotifyTo); err != nil {
			err = fmt.Errorf("%s: NotifyTo: %v", e, err)
			break
		}

		if err = validateConfigOp(op.MirrorTo); err != nil {
			err = fmt.Errorf("%s: MirrorTo: %v", e, err)
			break
		}
	}

	return
}

func validateConfigOp(mail []string) (err error) {

	for _, m := range mail {
		if !reMail.MatchString(m) {
			err = fmt.Errorf("invalid mail: %s", m)
			break
		}
	}

	return
}
