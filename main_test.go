package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"git.vsu.ru/ai/rspamd-cgp/config"
	"git.vsu.ru/ai/rspamd-cgp/rspamc"
)

func TestIntegration_FullMatrix(t *testing.T) {
	// 1. Подготовка бинарника
	_, filename, _, _ := runtime.Caller(0)
	testSrcDir := filepath.Dir(filename)
	helperPath, _ := filepath.Abs(filepath.Join(testSrcDir, "rspamd-cgp"))

	if _, err := os.Stat(helperPath); os.IsNotExist(err) {
		t.Fatalf("Helper binary not found. Build it: go build -o rspamd-cgp")
	}

	type testCase struct {
		name       string
		isOutbound bool
		rspamdResp string
		configYaml string
		expect     []string // Ожидаемые подстроки в ответе хелпера
		checkFile  bool     // Нужно ли проверять наличие .sub файла
	}

	matrix := []testCase{
		{
			name:       "1. IN: Clean Message",
			rspamdResp: `{"action":"no action","score":0.1,"symbols":{"ALL_OK":{"score":0}}}`,
			configYaml: "authservid: \"domain.name\"\nhost: \"%s\"\nnotifyfrom: \"p@v.ru\"\n",
			expect:     []string{"2 OK"},
		},
		{
			name:       "2. IN: Virus -> Mirror + Discard",
			rspamdResp: `{"action":"no action","symbols":{"VIRUS":{"score":10}}}`,
			configYaml: "authservid: \"domain.name\"\nhost: \"%s\"\nnotifyfrom: \"p@v.ru\"\nsymbols:\n  VIRUS: { discard: true, mirrorto: [\"quarantine@domain.name\"] }\n",
			expect:     []string{"MIRRORTO", "quarantine@domain.name", "DISCARD"},
		},
		{
			name:       "3. IN: Spam -> Rewrite Subject",
			rspamdResp: `{"action":"rewrite subject","subject":"[SPAM] Test","score":8,"symbols":{"SPAM_LOW":{"score":5}}}`,
			configYaml: "authservid: \"domain.name\"\nhost: \"%s\"\nnotifyfrom: \"p@v.ru\"\nsymbols:\n  SPAM_LOW: { Discard: true }\n",
			expect:     []string{"2 ADDHEADER", "DISCARD"},
			checkFile:  true,
		},
		{
			name:       "4. IN: High Score -> Reject Action (Junk-Score)",
			rspamdResp: `{"action":"reject","score":15}`,
			configYaml: "authservid: \"domain.name\"\nhost: \"%s\"\nnotifyfrom: \"p@v.ru\"\n",
			expect:     []string{"ADDHEADER", "X-Junk-Score: [XXXXXXXXXX]", "OK"},
		},
		{
			name:       "5. OUT: Virus -> Discard (No Mirror for outbound)",
			isOutbound: true,
			rspamdResp: `{"action":"no action","symbols":{"VIRUS":{"score":10}}}`,
			configYaml: "authservid: \"domain.name\"\nhost: \"%s\"\nnotifyfrom: \"p@v.ru\"\nsymbols:\n  VIRUS: { discard: true, mirrorto: [\"quarantine@domain.name\"] }\n",
			expect:     []string{"DISCARD"},
		},
	}

	for _, tc := range matrix {
		t.Run(tc.name, func(t *testing.T) {
			// Создаем песочницу
			tmpDir := t.TempDir()
			os.MkdirAll(filepath.Join(tmpDir, "Queue"), 0777)
			os.MkdirAll(filepath.Join(tmpDir, "Submitted"), 0777)

			// Поднимаем эмулятор Rspamd
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, tc.rspamdResp)
			}))
			defer ts.Close()

			// Пишем конфиг
			confPath := filepath.Join(tmpDir, "config.yml")
			os.WriteFile(confPath, []byte(fmt.Sprintf(tc.configYaml, strings.TrimPrefix(ts.URL, "http://"))), 0644)

			// Создаем письмо
			qid := "999"
			msgPath := filepath.Join(tmpDir, "Queue", qid+".msg")
			msgData := "S <s@v.ru> SMTP [1.1.1.1]\nP <s@v.ru>\nR <r@v.ru>\n\n" +
				"Received: from x by domain.name; Thu, 05 Mar 2026 12:00:00 +0300\n" +
				"From: s@v.ru\nSubject: Test\n\nBody content"
			os.WriteFile(msgPath, []byte(msgData), 0644)

			// Запуск хелпера
			args := []string{"-config", confPath}
			if tc.isOutbound {
				args = append(args, "-outbound")
			}
			cmd := exec.Command(helperPath, args...)
			cmd.Dir = tmpDir

			stdin, _ := cmd.StdinPipe()
			stdout, _ := cmd.StdoutPipe()
			stderrReader, _ := cmd.StderrPipe()

			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}

			// Читаем stderr, чтобы не блокировать процесс
			go io.Copy(io.Discard, stderrReader)

			// Читаем результат
			resChan := make(chan string)
			go func() {
				scanner := bufio.NewScanner(stdout)
				for scanner.Scan() {
					line := scanner.Text()
					if len(line) > 0 && line[0] >= '0' && line[0] <= '9' && !strings.Contains(line, "INTF") {
						resChan <- line
						return
					}
				}
			}()

			// Команды протокола
			fmt.Fprint(stdin, "1 INTF 4\n")
			fmt.Fprintf(stdin, "2 FILE Queue/%s.msg\n", qid)

			select {
			case res := <-resChan:
				for _, exp := range tc.expect {
					if !strings.Contains(res, exp) {
						t.Errorf("[%s] Expected '%s', got: %s", tc.name, exp, res)
					}
				}
			case <-time.After(3 * time.Second):
				cmd.Process.Kill()
				t.Fatalf("[%s] Timeout waiting for response", tc.name)
			}

			// Проверка файла в Submitted
			if tc.checkFile {
				subPath := filepath.Join(tmpDir, "Submitted", qid+"rs.sub")
				if _, err := os.Stat(subPath); os.IsNotExist(err) {
					t.Errorf("[%s] File %s not created!", tc.name, subPath)
				}
			}

			fmt.Fprint(stdin, "3 QUIT\n")
			stdin.Close()
			cmd.Wait()
		})
	}
}

func createCgpCompliantFile(t *testing.T, qid int) string {
	path := filepath.Join(os.TempDir(), fmt.Sprintf("%d.msg", qid))

	var buf bytes.Buffer
	// 1. Формат CGP Envelope
	buf.WriteString("S <test@domain.name> SMTP [2001:67c:418:2020::21]\n")
	buf.WriteString(fmt.Sprintf("P <%d@domain.name>\n", qid))
	buf.WriteString("R <rcpt@domain.name>\n")
	buf.WriteString("\n") // Конец Envelope

	// 2. Тело письма (RFC5322)
	buf.WriteString("Received: from mail.domain.name ([1.2.3.4] verified)\n")
	buf.WriteString("From: <sender@domain.name>\n")
	buf.WriteString("Subject: Bench\n")
	buf.WriteString("\n")
	buf.WriteString("Body content goes here")

	os.WriteFile(path, buf.Bytes(), 0644)
	return path
}

func BenchmarkRspamc_Scan_RealWork(b *testing.B) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"action": "no action", "score": -2.75, "symbols": {"RCPTS_DOMAINS_LOCAL": {"options": ["domain.name"]}}}`)
	}))
	defer ts.Close()

	// Создаем правильный файл
	tmpMsg := createCgpCompliantFile(nil, 555)
	defer os.Remove(tmpMsg)

	// Глушим syscall.Write
	null, _ := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	oldStdout, _ := syscall.Dup(1)
	syscall.Dup2(int(null.Fd()), 1)

	oldArgs := os.Args
	os.Args = []string{"rspamd-cgp"}
	defer func() { os.Args = oldArgs }()

	conf, err := config.New(os.Args[1:])
	if err != nil {
		os.Stderr.WriteString("config: " + err.Error() + "\n")
		os.Exit(1)
	}
	config.SetGlobal(conf)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		rspamc.Scan(i, tmpMsg)
	}

	syscall.Dup2(oldStdout, 1)
}
