package rspamc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"git.vsu.ru/ai/rspamd-cgp/config"
)

func TestScan_HttpRequestConstruction(t *testing.T) {
	// Создаем тестовое сообщение
	tmpDir := t.TempDir()
	msgPath := filepath.Join(tmpDir, "100.msg")
	// Важно: HdrPos будет 24 (после \n\n)
	os.WriteFile(msgPath, []byte("P <s@vsu.ru>\nR <r@vsu.ru>\n\nFrom: s@vsu.ru\n\nBody"), 0644)

	// Проверяем, что заголовки из CGP Message долетели до Rspamd
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// CommuniGate хранит адреса в скобках, проверяем именно этот вариант
		expectedFrom := "<s@vsu.ru>"
		if r.Header.Get("From") != expectedFrom {
			t.Errorf("Expected From header %s, got %s", expectedFrom, r.Header.Get("From"))
		}
		if r.Header.Get("MTA-Tag") != "test-mta" {
			t.Errorf("Expected MTA-Tag, got %s", r.Header.Get("MTA-Tag"))
		}

		// Возвращаем мок-ответ
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(RspamdResponse{
			Action: "no action",
			Score:  0.1,
		})
	}))
	defer ts.Close()

	// Настраиваем конфиг на этот сервер
	conf := &config.Config{
		Host:       ts.URL,
		AuthservId: "test-mta",
		NotifyFrom: "postmaster@vsu.ru",
	}
	config.SetGlobal(conf)

	// Запускаем скан.
	// Мы не проверяем stdout (это требует сложного перехвата),
	// но убеждаемся, что цепочка вызовов проходит без ошибок и паник.
	Scan(1, msgPath)
}

func TestRspamdResponse_Unmarshalling(t *testing.T) {
	// Проверяем, что наша структура корректно ест сложный JSON от Rspamd
	rawJSON := `{
		"action": "add header",
		"score": 5.5,
		"required_score": 7.0,
		"milter": {
			"add_headers": {
				"X-Spam": {"value": "Yes"}
			}
		},
		"symbols": {
			"TEST_SYM": {"score": 1.2, "description": "some sym"}
		}
	}`

	var res RspamdResponse
	err := json.Unmarshal([]byte(rawJSON), &res)
	if err != nil {
		t.Fatalf("Unmarshall failed: %v", err)
	}

	if res.Milter.AddHeaders["X-Spam"].Value != "Yes" {
		t.Error("Failed to parse milter headers")
	}
	if res.Symbols["TEST_SYM"].Score != 1.2 {
		t.Error("Failed to parse symbols")
	}
}
