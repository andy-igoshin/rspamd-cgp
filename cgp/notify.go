package cgp

import (
	"bytes"
	"os"
	"strconv"
	"strings"
	"time"
)

func NotifyTo(seq int, qid int, to []string, header string, from string, rcpts []string,
	body []byte, notifyfrom string, desc string) {

	date := time.Now().Format(time.RFC1123Z)
	mailid := strconv.Itoa(qid)
	boundary := "nextPart" + mailid + "." + strconv.Itoa(seq)
	off := bytes.Index(body, []byte("\n\n"))

	var sb strings.Builder
	sb.Grow(2048 + off)

	sb.WriteString("Return-Path: <>\n")
	for _, rcpt := range to {
		sb.WriteString("Envelope-To: " + rcpt + "\n")
	}
	sb.WriteString("From: " + notifyfrom + "\n")
	sb.WriteString("Subject: Notify Case " + mailid + "\n")
	sb.WriteString("Date: " + date + "\n")
	sb.WriteString(header + "\n")
	sb.WriteString("MIME-Version: 1.0\n")
	sb.WriteString("Content-Type: multipart/mixed; boundary=\"" + boundary + "\"\n")
	sb.WriteString("\n")

	sb.WriteString("This is a multi-part message in MIME format.\n\n")

	sb.WriteString("--" + boundary + "\n")
	sb.WriteString("Content-Type: text/plain; charset=UTF-8; format=flowed\n")
	sb.WriteString("Content-Transfer-Encoding: 8bit\n")
	sb.WriteString("\n")

	sb.WriteString("mail id:   " + mailid + "\n")
	sb.WriteString("mail from: " + from + "\n")

	sb.WriteString("rcpt to:   " + rcpts[0] + "\n")
	for _, rcpt := range rcpts[1:] {
		sb.WriteString("           " + rcpt + "\n")
	}

	sb.WriteString("date:      " + date + "\n")
	sb.WriteString("\n")

	sb.WriteString("case conditions:\n")
	sb.WriteString("----------------\n")
	sb.WriteString(desc + "\n")
	sb.WriteString("\n\n\n")

	sb.WriteString("--" + boundary + "\n")
	sb.WriteString("Content-Disposition: attachment; filename=\"headers\"\n")
	sb.WriteString("Content-Type: text/plain; charset=UTF-8\n")
	sb.WriteString("Content-Transfer-Encoding: 8bit\n")
	sb.WriteString("\n")

	sb.Write(body[:off+1])

	sb.WriteString("\n")
	sb.WriteString("--" + boundary + "--\n")

	filename := submitDir + "/" + mailid + "no.sub"
	filetemp := strings.Replace(filename, "sub", "tmp", 1)

	fh, err := os.Create(filetemp)
	if err != nil {
		goto fin
	}
	defer fh.Close()

	_, err = fh.WriteString(sb.String())
	if err != nil {
		goto fin
	}

	if err = fh.Close(); err != nil {
		goto fin
	}

	err = os.Rename(filetemp, filename)

fin:
	if err != nil {
		Putline("* %d [%d]: notify: %s\n", seq, qid, err)
	}
}
