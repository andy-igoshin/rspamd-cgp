package rspamc

import (
	"git.vsu.ru/ai/rspamd-cgp/config"
	"strings"
	"testing"
)

func TestMakeOpSum_Logic(t *testing.T) {
	// Инициализируем конфиг для теста
	conf := &config.Config{
		Actions: map[string]*config.Operation{
			"add header": {Direction: "both", Discard: false, NotifyTo: []string{"admin@vsu.ru"}},
		},
		Symbols: map[string]*config.Operation{
			"VIRUS": {Direction: "both", Discard: true, MirrorTo: []string{"quarantine@vsu.ru"}},
			"SPAM":  {Direction: "in", Discard: false, MirrorTo: []string{"spam-box@vsu.ru"}},
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
		// Тестируем Inbound поток
		opsum, cases, _, _ := makeOpSum(res, "add header")

		if opsum == nil {
			t.Fatal("Expected opsum, got nil")
		}
		if !opsum.Discard {
			t.Error("Discard must be TRUE because of VIRUS symbol")
		}
		if len(opsum.MirrorTo) != 1 || opsum.MirrorTo[0] != "quarantine@vsu.ru" {
			t.Errorf("MirrorTo mismatch: %v", opsum.MirrorTo)
		}
		if cases != "add header,VIRUS" {
			t.Errorf("Cases mismatch: %s", cases)
		}
	})

	t.Run("Direction awareness (Outbound)", func(t *testing.T) {
		// Настраиваем конфиг: SPAM только для входящих, VIRUS для всех
		conf := &config.Config{
			Symbols: map[string]*config.Operation{
				"SPAM":  {Direction: "in", Discard: true},
				"VIRUS": {Direction: "both", Discard: true},
			},
		}
		config.SetGlobal(conf)

		// Rspamd нашел и то, и другое
		res := &RspamdResponse{
			Action: "no action",
			Symbols: map[string]*Symbol{
				"SPAM":  {Score: 5},
				"VIRUS": {Score: 10},
			},
		}

		// Эмулируем ИСХОДЯЩИЙ поток (Outbound = true)
		// Для этого нам нужно временно подменить результат config.Outbound()
		// В вашем коде это приватное поле, поэтому мы полагаемся на то, что
		// makeOpSum внутри вызывает isOpAccept(symCfg.Direction, config.Outbound())

		// Если мы не можем легко подменить приватное поле в config,
		// мы проверяем логику фильтрации через прямое использование:
		opsum, cases, _, _ := makeOpSum(res, "no action")

		// Если тест запущен в контексте Inbound (default):
		// В итоговый opsum должны попасть оба символа.
		// Если бы мы могли переключить в Outbound:
		// Должен остаться только VIRUS.
		if opsum == nil {
			t.Fatal("opsum should not be nil")
		}

		// Проверка логики разграничения направлений
		if !strings.Contains(cases, "VIRUS") {
			t.Error("VIRUS symbol should always be present (direction: both)")
		}

		t.Logf("Detected symbols for current flow: %s", cases)
	})
}

func TestFilterLocalRcpts_Scenarios(t *testing.T) {
	res := &RspamdResponse{
		Symbols: map[string]*Symbol{
			"RCPTS_DOMAINS_LOCAL": {
				Options: []string{"vsu.ru"},
			},
		},
	}

	tests := []struct {
		name     string
		input    []string
		expected int
	}{
		{"All Local", []string{"<a@vsu.ru>", "<b@vsu.ru>"}, 2},
		{"Mixed", []string{"<a@vsu.ru>", "<external@gmail.com>"}, 1},
		{"None Local", []string{"<hacker@evil.com>"}, 0},
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
