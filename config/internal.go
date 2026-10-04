package config

import (
	"fmt"
	"regexp"

	"gopkg.in/yaml.v3"
)

var reMail *regexp.Regexp

func dumpConfig(c *Config) {
	yml, err := yaml.Marshal(c)
	if err != nil {
		fmt.Println("config:", err)
	} else {
		fmt.Print(string(yml))
		fmt.Println("debug:", c.debug)
		fmt.Println("outbound:", c.outbound)
		fmt.Println("showVersion:", c.showVersion)
	}
}

func validateConfig(c *Config) (err error) {

	reMail = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)

	if err = validateConfigOp(c.NotifyFrom); err != nil {
		return
	}

	if err = validateConfigEntry(c.Actions); err != nil {
		return
	}

	if err = validateConfigEntry(c.Symbols); err != nil {
		return
	}

	return
}

func validateConfigEntry(entry map[string]*Operation) (err error) {

	for e, op := range entry {

		// Проверка диапазона Direction
		if op.Direction < DirBoth || op.Direction > DirOut {
			return fmt.Errorf("%s: invalid direction index: %d", e, op.Direction)
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
			break
		}
	}

	return
}
