package cgp

import (
	"bufio"
	"io"
	"os"
	"strconv"
	"time"
)

func NotifyTo(seq int, m *Message, to []string, header string, notifyfrom string, desc string) {
	mailid := strconv.Itoa(m.QID)
	sSeq := strconv.Itoa(seq)
	filename := submitDir + "/" + mailid + "no.sub"
	filetemp := submitDir + "/" + mailid + "no.tmp"

	// Локальная функция-обертка для изоляции ресурсов (File, Writer)
	err := func() error {
		fh, err := os.Create(filetemp)
		if err != nil {
			return err
		}
		defer fh.Close()

		w := bufio.NewWriterSize(fh, 8192)
		defer w.Flush()

		date := time.Now().Format(time.RFC1123Z)
		boundary := "nextPart" + mailid + "." + sSeq

		// 1. Конверт и заголовки MIME
		w.WriteString("Return-Path: <>\n")
		for _, rcpt := range to {
			w.WriteString("Envelope-To: ")
			w.WriteString(rcpt)
			w.WriteByte('\n')
		}
		w.WriteString("From: ")
		w.WriteString(notifyfrom)
		w.WriteString("\nSubject: Notify Case ")
		w.WriteString(mailid)
		w.WriteString("\nDate: ")
		w.WriteString(date)
		w.WriteByte('\n')
		w.WriteString(header) // X-Rspamd-Case
		w.WriteString("\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=\"")
		w.WriteString(boundary)
		w.WriteString("\"\n\nThis is a multi-part message in MIME format.\n\n--")
		w.WriteString(boundary)

		// 2. Текстовое описание кейса
		w.WriteString("\nContent-Type: text/plain; charset=UTF-8; format=flowed\nContent-Transfer-Encoding: 8bit\n\nmail id:   ")
		w.WriteString(mailid)
		w.WriteString("\nmail from: ")
		w.WriteString(m.From)

		if len(m.Rcpts) > 0 {
			w.WriteString("\nrcpt to:   ")
			w.WriteString(m.Rcpts[0])
			for _, rcpt := range m.Rcpts[1:] {
				w.WriteString("\n           ")
				w.WriteString(rcpt)
			}
		}

		w.WriteString("\ndate:      ")
		w.WriteString(date)
		w.WriteString("\n\ncase conditions:\n----------------\n")
		w.WriteString(desc)
		w.WriteString("\n\n\n--")
		w.WriteString(boundary)

		// 3. Аттачмент (Оригинальные RFC заголовки)
		w.WriteString("\nContent-Disposition: attachment; filename=\"headers\"\nContent-Type: text/plain; charset=UTF-8\nContent-Transfer-Encoding: 8bit\n\n")

		hdrSize := m.BodyPos - m.HdrPos
		if hdrSize > 0 {
			sr := io.NewSectionReader(m.File, m.HdrPos, hdrSize)
			if _, err = io.Copy(w, sr); err != nil {
				return err
			}
		}

		w.WriteString("\n--")
		w.WriteString(boundary)
		w.WriteString("--\n")

		// Явный Flush и Close для проверки ошибок записи перед завершением функции
		if err = w.Flush(); err != nil {
			return err
		}
		return fh.Close()
	}()

	// Финализация: если была ошибка — чистим временный файл, если нет — переименовываем
	if err != nil {
		os.Remove(filetemp)
		Putline("* ", sSeq, " [", mailid, "]: notify: ", err)
		return
	}

	if err = os.Rename(filetemp, filename); err != nil {
		os.Remove(filetemp)
		Putline("* ", sSeq, " [", mailid, "]: notify rename error: ", err)
	}
}
