package cgp

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMainDomain(t *testing.T) {
	tmpDir := t.TempDir()
	err := os.MkdirAll(filepath.Join(tmpDir, "Settings"), 0755)
	if err != nil {
		t.Fatal(err)
	}

	// Тестируем разные варианты написания в Main.settings
	content := []byte(`
		OtherKey = 123;
		DomainName = "relay1.domain.name" ;
		UnquotedDomain = domain.name;
		# CommentedDomain = ignore.me;
	`)

	settingsPath := filepath.Join(tmpDir, "Settings", "Main.settings")
	if err := os.WriteFile(settingsPath, content, 0644); err != nil {
		t.Fatal(err)
	}

	// Подменяем рабочую директорию
	oldWd, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(oldWd)

	t.Run("Extract Quoted Domain", func(t *testing.T) {
		got, err := MainDomain()
		if err != nil {
			t.Fatalf("MainDomain failed: %v", err)
		}
		if got != "relay1.domain.name" {
			t.Errorf("Got %q, want %q", got, "relay1.domain.name")
		}
	})
}

func TestProtocolCommands(t *testing.T) {
	// Создаем pipe, чтобы перехватить то, что функции пишут в stdoutFd
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()

	// Сохраняем старый дескриптор и подменяем на наш pipe
	oldFd := stdoutFd
	stdoutFd = int(w.Fd())
	defer func() { stdoutFd = oldFd }()

	tests := []struct {
		name string
		fn   func()
		want string
	}{
		{
			name: "Ok command",
			fn:   func() { Ok(123) },
			want: "123 OK\n",
		},
		{
			name: "Discard command",
			fn:   func() { Discard(456) },
			want: "456 DISCARD\n",
		},
		{
			name: "Reject command",
			fn:   func() { Reject(789) },
			want: "789 REJECT Try again later\n",
		},
		{
			name: "Failure command",
			fn:   func() { Failure(10, 200, fmt.Errorf("test error")) },
			want: "* 10 [200]: test error\n10 FAILURE\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.fn()

			buf := make([]byte, 256)
			n, _ := r.Read(buf)
			got := string(buf[:n])

			if got != tt.want {
				t.Errorf("Got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAddHeader_ProtocolHandling(t *testing.T) {
	r, w, _ := os.Pipe()
	oldFd := stdoutFd
	stdoutFd = int(w.Fd())
	defer func() { stdoutFd = oldFd }()

	t.Run("Protocol v4 with OK", func(t *testing.T) {
		protocol = 4
		AddHeader(1, []string{"X-Test: True"})

		buf := make([]byte, 256)
		n, _ := r.Read(buf)
		got := string(buf[:n])

		if !strings.Contains(got, "\" OK\n") {
			t.Errorf("Protocol v4 should append OK, got: %q", got)
		}
	})
}

func TestPutline(t *testing.T) {
	r, w, _ := os.Pipe()
	oldFd := stdoutFd
	stdoutFd = int(w.Fd())
	defer func() { stdoutFd = oldFd }()

	t.Run("Variadic mixed types", func(t *testing.T) {
		Putline("* ", 1, " error: ", fmt.Errorf("fail"))

		buf := make([]byte, 256)
		n, _ := r.Read(buf)
		got := string(buf[:n])

		want := "* 1 error: fail\n"
		if got != want {
			t.Errorf("Putline mismatch. Got %q, want %q", got, want)
		}
	})
}
