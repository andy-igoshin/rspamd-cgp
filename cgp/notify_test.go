package cgp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNotifyTo(t *testing.T) {
	tmpDir := t.TempDir()
	subDir := filepath.Join(tmpDir, submitDir)
	os.MkdirAll(subDir, 0755)

	oldWd, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(oldWd)

	// 1. Готовим "донорское" письмо, из которого будем брать заголовки
	qid := 999
	mock := &MessageMock{
		Envelope: []string{"P <s@vsu.ru>", "R <r@vsu.ru>", "S SMTP [1.2.3.4]"},
		Headers:  []string{"From: sender@vsu.ru", "Subject: Original", "X-Custom: Value"},
		Body:     "This body should NOT be in notification",
	}
	fname := createTestFile(t, qid, mock.Render())

	msg, err := NewMessage(1, fname)
	if err != nil {
		t.Fatal(err)
	}
	defer msg.Close()

	// 2. Вызываем NotifyTo
	to := []string{"admin@vsu.ru"}
	notifyFrom := "postmaster@vsu.ru"
	desc := "Spam policy violation detected"
	header := "X-Rspamd-Case: 12345"

	NotifyTo(1, msg, to, header, notifyFrom, desc)

	// 3. Проверяем результат
	resPath := filepath.Join(subDir, "999no.sub")
	res, err := os.ReadFile(resPath)
	if err != nil {
		t.Fatalf("Notification file not created: %v", err)
	}
	sRes := string(res)

	// ПРОВЕРКИ:

	// А. Конверт (NotifyTo пишет Return-Path: <>)
	if !strings.HasPrefix(sRes, "Return-Path: <>\nEnvelope-To: admin@vsu.ru") {
		t.Error("Invalid envelope in notification")
	}

	// Б. MIME Boundary
	boundaryLine := "boundary=\"nextPart999.1\""
	if !strings.Contains(sRes, boundaryLine) {
		t.Errorf("Boundary definition not found. Expected: %s", boundaryLine)
	}

	// В. Текстовое описание
	if !strings.Contains(sRes, desc) || !strings.Contains(sRes, "mail id:    999") {
		t.Error("Description or Mail ID missing in notification body")
	}

	// Г. Аттачмент (Заголовки)
	// Проверяем, что заголовки из оригинала попали в аттачмент
	if !strings.Contains(sRes, "attachment; filename=\"headers\"") {
		t.Error("Attachment header missing")
	}
	if !strings.Contains(sRes, "X-Custom: Value") {
		t.Error("Original headers missing in attachment")
	}

	// Д. Отсутствие тела оригинала (Проверка SectionReader)
	if strings.Contains(sRes, "This body should NOT be in notification") {
		t.Error("Original body leaked into notification headers attachment")
	}

	// Е. Закрывающий boundary
	finalBoundary := "--nextPart999.1--"
	if !strings.Contains(sRes, finalBoundary) {
		t.Error("Final MIME boundary missing")
	}
}

func TestNotifyTo_MultipleRcpts(t *testing.T) {
	tmpDir := t.TempDir()
	subDir := filepath.Join(tmpDir, submitDir)
	os.MkdirAll(subDir, 0755)

	oldWd, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(oldWd)

	// Создаем сообщение с двумя получателями в конверте
	mock := &MessageMock{
		Envelope: []string{
			"P <s@vsu.ru>",
			"R <r1@vsu.ru>",
			"R <r2@vsu.ru>",
			"S SMTP [1.1.1.1]",
		},
		Headers: []string{"Subject: Test"},
		Body:    "Body",
	}
	qid := 123
	fname := createTestFile(t, qid, mock.Render())
	msg, err := NewMessage(1, fname)
	if err != nil {
		t.Fatalf("Failed to create message: %v", err)
	}
	defer msg.Close()

	// Получатели уведомления
	to := []string{"admin1@vsu.ru", "admin2@vsu.ru"}

	// Вызываем генерацию уведомления
	NotifyTo(1, msg, to, "X-Rspamd-Scan: 1", "postmaster@vsu.ru", "Policy violation")

	// Читаем результат
	resPath := filepath.Join(subDir, "123no.sub")
	res, err := os.ReadFile(resPath)
	if err != nil {
		t.Fatalf("Notification file not found: %v", err)
	}
	sRes := string(res)

	// 1. Проверка Envelope-To (оба адреса должны быть в заголовках конверта)
	if !strings.Contains(sRes, "Envelope-To: admin1@vsu.ru") ||
		!strings.Contains(sRes, "Envelope-To: admin2@vsu.ru") {
		t.Error("Not all notification recipients found in Envelope-To")
	}

	// 2. Проверка форматирования списка получателей в текстовой части.
	// Судя по вашему дампу:
	// "rcpt to:   <r1@vsu.ru>" -> 3 пробела после двоеточия
	// "\n           <r2@vsu.ru>" -> 11 пробелов в начале строки

	expectedFirst := "rcpt to:   <r1@vsu.ru>"
	expectedSecond := "\n           <r2@vsu.ru>"

	if !strings.Contains(sRes, expectedFirst) {
		t.Errorf("First recipient line mismatch.\nWant: %q\nGot around: %q", expectedFirst, sRes[strings.Index(sRes, "rcpt to:"):strings.Index(sRes, "rcpt to:")+30])
	}

	if !strings.Contains(sRes, expectedSecond) {
		t.Errorf("Indentation for second recipient mismatch.\nWant: %q", expectedSecond)
	}

	// 3. Проверка mail from (также со скобками)
	if !strings.Contains(sRes, "mail from: <s@vsu.ru>") {
		t.Error("Mail from line mismatch")
	}
}
