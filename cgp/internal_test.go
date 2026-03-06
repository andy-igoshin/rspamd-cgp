package cgp

import (
	"bufio"
	"bytes"
	"strings"
	"testing"
)

func TestGetHeader_Folding(t *testing.T) {
	// Проверяем корректность сборки многострочных заголовков (RFC folding)
	raw := "Subject: This is a very long\n\t subject line\nNext-Header: value\n"
	rd := bufio.NewReader(strings.NewReader(raw))
	buf := new(bytes.Buffer)

	err := getHeader(rd, buf)
	if err != nil {
		t.Fatalf("getHeader failed: %v", err)
	}

	got := buf.String()
	// Должен захватить обе строки, так как вторая начинается с табуляции
	if !strings.Contains(got, "subject line") {
		t.Errorf("Header folding failed. Got: %q", got)
	}
	if strings.Contains(got, "Next-Header") {
		t.Error("getHeader read too far into the next header")
	}
}

func TestGetHelo_Variants(t *testing.T) {
	tests := []struct {
		name string
		hdr  string
		want string
	}{
		{"Standard verified", "Received: from mail.domain.name ([1.2.3.4] verified)\n", "mail.domain.name"},
		{"HELO in brackets", "Received: from [1.2.3.4] (HELO poseidonms.com)\n", "poseidonms.com"},
		{"Account and HELO", "Received: from [10.19.5.40] (account test@domain.name HELO test.domain.name)\n", "test.domain.name"},
		{"Malformed", "Received: from broken (", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getHelo([]byte(tt.hdr)); got != tt.want {
				t.Errorf("getHelo() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestReplaceSpecCharsBuf(t *testing.T) {
	buf := new(bytes.Buffer)
	input := "Path\\To\nFile\t\"Name\"\r"
	// \ -> \\, \n -> \e, \t -> \t, " -> \", \r -> skip
	expected := "Path\\\\To\\eFile\\t\\\"Name\\\""

	replaceSpecCharsBuf(buf, input)
	if buf.String() != expected {
		t.Errorf("replaceSpecCharsBuf failed.\nGot:  %q\nWant: %q", buf.String(), expected)
	}
}

func TestIsHeaderEnd(t *testing.T) {
	if !isHeaderEnd([]byte("\n")) {
		t.Error("Failed to detect LF as header end")
	}
	if !isHeaderEnd([]byte("\r\n")) {
		t.Error("Failed to detect CRLF as header end")
	}
	if isHeaderEnd([]byte("Subject: \n")) {
		t.Error("False positive for header end")
	}
}
