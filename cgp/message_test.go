package cgp

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// MessageMock помогает собирать тестовые файлы сообщений CGP в байтовый массив
type MessageMock struct {
	Envelope []string
	Headers  []string
	Body     string
}

func (m *MessageMock) Render() []byte {
	var sb strings.Builder
	// 1. Конверт
	for _, line := range m.Envelope {
		sb.WriteString(line)
		sb.WriteByte('\n')
	}
	sb.WriteByte('\n') // Пустая строка - признак конца конверта

	// 2. RFC Заголовки
	for _, line := range m.Headers {
		sb.WriteString(line)
		sb.WriteByte('\n')
	}
	sb.WriteByte('\n') // Пустая строка - признак конца заголовков

	// 3. Тело
	sb.WriteString(m.Body)

	return []byte(sb.String())
}

// createTestFile создает структуру папок Submitted и пишет туда файл сообщения
func createTestFile(t *testing.T, qid int, content []byte) string {
	tmpDir := t.TempDir()
	subDir := filepath.Join(tmpDir, submitDir)
	if err := os.MkdirAll(subDir, 0755); err != nil {
		t.Fatal(err)
	}

	filename := filepath.Join(subDir, strconv.Itoa(qid)+".msg")
	if err := os.WriteFile(filename, content, 0644); err != nil {
		t.Fatal(err)
	}
	return filename
}

func TestNewMessage_Parsing(t *testing.T) {
	rawRecv := "Received: from mail.vsu.ru ([1.2.3.4] verified)"
	mock := &MessageMock{
		Envelope: []string{
			"P <sender@vsu.ru>",
			"R <rcpt1@vsu.ru>",
			"R <rcpt2@vsu.ru>",
			"S SMTP [1.2.3.4]",
		},
		Headers: []string{
			rawRecv,
			"Subject: Test",
			"From: sender@vsu.ru",
		},
		Body: "Hello world!",
	}

	content := mock.Render()
	qid := 10001
	fname := createTestFile(t, qid, content)

	msg, err := NewMessage(1, fname)
	if err != nil {
		t.Fatalf("NewMessage failed: %v", err)
	}
	defer msg.Close()

	// Проверка извлечения данных
	if msg.QID != qid {
		t.Errorf("QID mismatch: got %d, want %d", msg.QID, qid)
	}
	if msg.From != "<sender@vsu.ru>" {
		t.Errorf("From mismatch: got %s", msg.From)
	}
	if len(msg.Rcpts) != 2 {
		t.Errorf("Rcpts count mismatch: got %d", len(msg.Rcpts))
	}
	if msg.IP != "1.2.3.4" {
		t.Errorf("IP mismatch: got %s", msg.IP)
	}
	if msg.Helo != "mail.vsu.ru" {
		t.Errorf("Helo mismatch: got %s", msg.Helo)
	}

	// Проверка смещений (HdrPos должен указывать на 'R' в 'Received')
	expectedHdrPos := int64(strings.Index(string(content), "Received:"))
	if msg.HdrPos != expectedHdrPos {
		t.Errorf("HdrPos: got %d, want %d", msg.HdrPos, expectedHdrPos)
	}

	// Проверка смещения тела (BodyPos после пустой строки после заголовков)
	expectedBodyPos := int64(strings.Index(string(content), "Hello world!"))
	if msg.BodyPos != expectedBodyPos {
		t.Errorf("BodyPos: got %d, want %d", msg.BodyPos, expectedBodyPos)
	}
}

func TestMessage_RewriteSubject(t *testing.T) {
	tmpDir := t.TempDir()
	subDir := filepath.Join(tmpDir, submitDir)
	os.MkdirAll(subDir, 0755)

	oldWd, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(oldWd)

	// Подготовка мока сообщения
	rawRecv := "Received: from mail.vsu.ru ([1.2.3.4] verified)"
	mock := &MessageMock{
		Envelope: []string{"P <s@vsu.ru>", "R <r@vsu.ru>", "S SMTP [1.2.3.4]"},
		Headers: []string{
			"From: s@vsu.ru",
			rawRecv, // Наш целевой Received для HELO и Seen
			"Subject: Old",
		},
		Body: "Body Content",
	}

	qid := 20002
	// Создаем тестовый файл .msg
	fname := createTestFile(t, qid, mock.Render())

	// 1. Инициализируем сообщение (должно найти внешний Received и сохранить его)
	msg, err := NewMessage(1, fname)
	if err != nil {
		t.Fatalf("NewMessage failed: %v", err)
	}
	defer msg.Close()

	// 2. Генерируем Seen-заголовок через метод структуры (логика rspamc)
	seenHeader := msg.MakeSeen()
	if len(seenHeader) == 0 {
		t.Fatalf("MakeSeen returned empty string, check if NewMessage saved rawReceived")
	}

	newSubj := "SPAM: Original"
	// Собираем слайс дополнительных заголовков
	rspamdHdrs := []string{
		"X-Spam-Score: 10.0",
		seenHeader, // Добавляем сгенерированный Seen
	}

	// 3. Выполняем рерайт в директорию Submitted
	err = msg.RewriteSubject(rspamdHdrs, newSubj)
	if err != nil {
		t.Fatalf("RewriteSubject failed: %v", err)
	}

	// 4. Проверяем результат в .sub файле
	resPath := filepath.Join(subDir, "20002rs.sub")
	res, err := os.ReadFile(resPath)
	if err != nil {
		t.Fatalf("Result file %s not found", resPath)
	}
	sRes := string(res)

	// А. Проверка хеша
	// Важно: hashReceived должен работать идентично внутри MakeSeen и здесь в тесте
	expectedHash := hashReceived([]byte(rawRecv + "\n"))
	if !strings.Contains(sRes, "X-Rspamd-Seen: "+expectedHash) {
		t.Errorf("Seen header missing or hash mismatch.\nExpected hash: %s\nFull content:\n%s", expectedHash, sRes)
	}

	// Б. Проверка замены темы
	expectedSubjLine := "Subject: " + newSubj
	if !strings.Contains(sRes, expectedSubjLine) {
		t.Errorf("New subject %q not found in file", expectedSubjLine)
	}

	// В. Проверка удаления старой темы
	if strings.Contains(sRes, "Subject: Old") {
		t.Error("Old subject 'Subject: Old' still present in the file!")
	}

	// Г. Проверка наличия заголовков из слайса
	if !strings.Contains(sRes, "X-Spam-Score: 10.0") {
		t.Error("Rspamd headers (X-Spam-Score) missing in rewritten file")
	}
}

func TestNewMessage_Malformed(t *testing.T) {
	t.Run("Unexpected EOF", func(t *testing.T) {
		// Обрываем файл прямо в середине конверта
		content := []byte("P <sender@vsu.ru>\nS SMTP [1.2.3.4]")
		fname := createTestFile(t, 30003, content)

		_, err := NewMessage(1, fname)
		if err == nil || !strings.Contains(err.Error(), "unexpected end of envelope") {
			t.Errorf("Expected EOF error, got: %v", err)
		}
	})
}
