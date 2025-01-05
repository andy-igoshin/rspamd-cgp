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

func setOpDefaultDirection(config *Config) {

	setDir := func(entry map[string]*Operation) {
		for _, op := range entry {
			if len(op.Direction) == 0 {
				op.Direction = "both"
			}
		}
	}

	setDir(config.Actions)
	setDir(config.Symbols)
}

func validateConfig(config *Config) (err error) {

	reMail = regexp.MustCompile(`^\S+?@\S+$`)

	if err = validateConfigOp(config.NotifyFrom); err != nil {
		return
	}

	if err = validateConfigEntry(config.Actions); err != nil {
		return
	}

	if err = validateConfigEntry(config.Symbols); err != nil {
		return
	}

	return
}

func validateConfigEntry(entry map[string]*Operation) (err error) {

	for e, op := range entry {

		if err = validateDirection(op.Direction); err != nil {
			err = fmt.Errorf("%s: Direction: %v", e, err)
			break
		}

		if err = validateConfigOps(op.NotifyTo); err != nil {
			err = fmt.Errorf("%s: NotifyTo: %v", e, err)
			break
		}

		if err = validateConfigOps(op.MirrorTo); err != nil {
			err = fmt.Errorf("%s: MirrorTo: %v", e, err)
			break
		}
	}

	return
}

func validateConfigOp(m string) (err error) {

	if !reMail.MatchString(m) {
		err = fmt.Errorf("invalid mail: %s", m)
	}

	return
}

func validateConfigOps(mail []string) (err error) {

	for _, m := range mail {
		if err = validateConfigOp(m); err != nil {
			err = fmt.Errorf("invalid mail: %s", m)
			break
		}
	}

	return
}

func validateDirection(dir string) (err error) {

	if dir != "both" && dir != "in" && dir != "out" && dir != "" {
		err = fmt.Errorf("unknown direction: %s", dir)
	}

	return
}
