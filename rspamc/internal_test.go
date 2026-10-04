package rspamc

import (
	"testing"

	"git.vsu.ru/ai/rspamd-cgp/config"
)

func TestMakeOpSum_Logic(t *testing.T) {
	// Инициализируем конфиг для теста
	conf := &config.Config{
		Actions: map[string]*config.Operation{
			"add header": {Direction: config.DirBoth, Discard: false, NotifyTo: []string{"admin@domain.name"}},
		},
		Symbols: map[string]*config.Operation{
			"VIRUS": {Direction: config.DirBoth, Discard: true, MirrorTo: []string{"quarantine@domain.name"}},
			"SPAM":  {Direction: config.DirIn, Discard: false, MirrorTo: []string{"spam-box@domain.name"}},
		},
	}
	config.SetGlobal(conf)

	t.Run("Merge Action and Virus Symbol", func(t *testing.T) {
		res := &RspamdResponse{
			Action: "add header",
			Symbols: map[string]*Symbol{
				"VIRUS": {Score: 10},
			},
		}

		// По умолчанию работаем как Inbound (config.outbound = false)
		opsum, cases, _, _ := makeOpSum(res, "add header")

		if opsum == nil {
			t.Fatal("Expected opsum, got nil")
		}
		if !opsum.Discard {
			t.Error("Discard must be TRUE because of VIRUS symbol")
		}
		if len(opsum.MirrorTo) != 1 || opsum.MirrorTo[0] != "quarantine@domain.name" {
			t.Errorf("MirrorTo mismatch: %v", opsum.MirrorTo)
		}
		if cases != "add header,VIRUS" {
			t.Errorf("Cases mismatch: %s", cases)
		}
	})

	t.Run("Direction awareness (Manual Check)", func(t *testing.T) {
		// Для этого теста проверим логику фильтрации напрямую через isOpAccept,
		// так как подменить глобальное состояние outbound без рефлексии или
		// пересоздания конфига через New() сложно.

		tests := []struct {
			name     string
			dir      config.Direction
			outbound bool
			want     bool
		}{
			{"Inbound: In accept", config.DirIn, false, true},
			{"Inbound: Out reject", config.DirOut, false, false},
			{"Inbound: Both accept", config.DirBoth, false, true},
			{"Outbound: In reject", config.DirIn, true, false},
			{"Outbound: Out accept", config.DirOut, true, true},
			{"Outbound: Both accept", config.DirBoth, true, true},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				if got := isOpAccept(tt.dir, tt.outbound); got != tt.want {
					t.Errorf("isOpAccept(%v, %v) = %v; want %v", tt.dir, tt.outbound, got, tt.want)
				}
			})
		}
	})
}

func TestFilterLocalRcpts_Scenarios(t *testing.T) {
	res := &RspamdResponse{
		Symbols: map[string]*Symbol{
			"RCPTS_DOMAINS_LOCAL": {
				Options: []string{"domain.name"},
			},
		},
	}

	tests := []struct {
		name     string
		input    []string
		expected int
	}{
		{"All Local", []string{"a@domain.name", "b@domain.name"}, 2},
		{"Mixed", []string{"a@domain.name", "external@gmail.com"}, 1},
		{"None Local", []string{"hacker@evil.com"}, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := filterLocalRcpts(tt.input, res)
			if len(out) != tt.expected {
				t.Errorf("Got %d, want %d for %s", len(out), tt.expected, tt.name)
			}
		})
	}
}
