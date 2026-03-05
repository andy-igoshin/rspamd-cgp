package config

import (
	"fmt"
)

type Direction int

const (
	DirBoth Direction = iota
	DirIn
	DirOut
)

// MarshalYAML позволяет Marshal печатать строку вместо числа
func (d Direction) MarshalYAML() (any, error) {
	return d.String(), nil
}

// String реализует интерфейс fmt.Stringer
func (d Direction) String() string {
	switch d {
	case DirIn:
		return "in"
	case DirOut:
		return "out"
	case DirBoth:
		return "both"
	default:
		return fmt.Sprintf("unknown(%d)", d)
	}
}

// UnmarshalYAML позволяет прозрачно читать "in", "out", "both" из конфига
func (d *Direction) UnmarshalYAML(unmarshal func(any) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	switch s {
	case "in":
		*d = DirIn
	case "out":
		*d = DirOut
	case "both", "": // Пустое значение трактуем как both
		*d = DirBoth
	default:
		return fmt.Errorf("invalid direction: %s (want: in, out, both)", s)
	}
	return nil
}
