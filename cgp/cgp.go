package cgp

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"unicode"
)

const recvHdr = "Received:"
const seenHdr = "X-Rspamd-Seen:"
const subjHdr = "Subject:"
const submitDir = "Submitted"

var MainDomain string
var reMD *regexp.Regexp
var reSELF *regexp.Regexp
var reSMTP *regexp.Regexp
var protocol int

func init() {
	reMD = regexp.MustCompile(`^\s+DomainName\s+=\s+([^;]+);`)
	reSELF = regexp.MustCompile(`^S (?:<([^>]+)> )?(?:DSN|GROUP|LIST|PBX|PIPE|RULE) \[0\.0\.0\.0\]`)
	reSMTP = regexp.MustCompile(`^S (?:<([^>]+)> )?(?:SMTP|HTTPU?|AIRSYNC|XIMSS) \[([0-9a-f.:]+)\]`)

	err := setMainDomain()
	if err != nil {
		Putline("* Can not detect Main Domain: %v\n", err)
	}
}

func AddHeader(seq int, headers []string) {

	hdrs := replaceSpecChars(strings.Join(headers, "\n"))

	if protocol >= 4 {
		Putline("%d ADDHEADER \"%s\" OK\n", seq, hdrs)
	} else {
		Putline("%d ADDHEADER \"%s\"\n", seq, hdrs)
	}
}

func Discard(seq int) {
	Putline("%d DISCARD\n", seq)
}

func Failure(seq, qid int, err error) {
	Putline("* %d [%d]: %s\n", seq, qid, err)
	Putline("%d FAILURE\n", seq)
}

func Intf(seq int, ver string) {
	protocol, _ = strconv.Atoi(ver)
	Putline("%d INTF %d\n", seq, protocol)
}

func Message(filename string) (from string, rcpts []string, auth string, ip string, qid int, body []byte, seen bool, err error) {

	qid, err = strconv.Atoi((filename)[strings.LastIndexByte(filename, '/')+1 : strings.LastIndexByte(filename, '.')])
	if err != nil {
		return
	}

	h, err := os.Open(filename)
	if err != nil {
		return
	}
	defer h.Close()

	var line []byte
	var pos int64

	m := bufio.NewReader(h)

	for {

		line, err = m.ReadSlice('\n')
		if err != nil {
			return
		}

		pos += int64(len(line))

		if string(line) == "\n" {
			break
		}

		switch line[0] {
		case 'P':
			s := strings.IndexByte(string(line), '<')
			from = string(line[s : s+strings.IndexByte(string(line[s:]), '>')+1])

		case 'R':
			s := strings.IndexByte(string(line), '<')
			rcpts = append(rcpts, string(line[s:s+strings.IndexByte(string(line[s:]), '>')+1]))

		case 'S':
			if s := reSMTP.FindAllStringSubmatch(string(line), -1); s != nil {
				auth = s[0][1]
				ip = s[0][2]
			} else if s := reSELF.FindAllStringSubmatch(string(line), -1); s != nil {
				auth = s[0][1]
				ip = "127.2.4.7"
			}
		}
	}

	seen, err = isSeen(m)
	if err != nil {
		return
	}

	if seen {
		return
	}

	fi, err := h.Stat()
	if err != nil {
		return
	}

	_, err = h.Seek(pos, os.SEEK_SET)
	if err != nil {
		return
	}

	body = make([]byte, fi.Size()-pos)
	n, err := h.Read(body)
	if err != nil {
		return
	}

	rcpts = uniqueNonEmptyElementsOf(rcpts)

	if from == "" || len(rcpts) == 0 || n < len(body) {
		err = fmt.Errorf("cgp.Message() error: from='%s', len(to)=%d, auth='%s' ip='%s', size=%d/%d", from, len(rcpts), auth, ip, len(body), n)
	}

	return
}

func MirrorTo(seq int, to []string, headers []string, mirrorDiscard bool) {

	hdrs := replaceSpecChars(strings.Join(headers, "\n"))

	if protocol >= 4 {

		if len(to) > 0 {

			mirrorTo := []string{}
			for _, m := range to {
				mirrorTo = append(mirrorTo, fmt.Sprintf("MIRRORTO \"%s\"", m))
			}

			if mirrorDiscard {
				Putline("%d ADDHEADER \"%s\" %s DISCARD\n", seq, hdrs, strings.Join(mirrorTo, " "))
			} else {
				Putline("%d ADDHEADER \"%s\" %s OK\n", seq, hdrs, strings.Join(mirrorTo, " "))
			}

		} else {
			Putline("%d ADDHEADER \"%s\" OK\n", seq, hdrs)
		}

	} else {
		Putline("%d ADDHEADER \"%s\"\n", seq, hdrs)
	}
}

func Ok(seq int) {
	Putline("%d OK\n", seq)
}

func OkSeen(seq, qid int) {
	Putline("* %d [%d]: Already seen by Rspamd\n", seq, qid)
	Putline("%d OK\n", seq)
}

func Putline(format string, a ...interface{}) {
	s := fmt.Sprintf(format, a...)
	syscall.Write(int(os.Stdout.Fd()), []byte(s))
}

func Reject(seq int) {
	Putline("%d REJECT Try again later\n", seq)
}

func RewriteSubject(seq int, headers []string, subject string, qid int, from string, rcpts []string, body []byte) {

	var err error
	var firstRecv bool = true
	var line []byte
	var m *bufio.Reader
	var hdr string

	filename := fmt.Sprintf("%s/%drs.sub", submitDir, qid)
	filetemp := strings.Replace(filename, "sub", "tmp", 1)

	fh, err := os.Create(filetemp)
	if err != nil {
		goto fin
	}
	defer fh.Close()

	_, err = fh.WriteString(strings.Join([]string{"Return-Path: ", from, "\n"}, ""))
	if err != nil {
		goto fin
	}

	for _, rcpt := range rcpts {
		_, err = fh.WriteString(strings.Join([]string{"Envelope-To: ", rcpt, "\n"}, ""))
		if err != nil {
			goto fin
		}
	}

	for _, hdr = range headers {
		_, err = fh.WriteString(hdr)
		if err != nil {
			goto fin
		}
	}

	m = bufio.NewReader(bytes.NewReader(body))

	for {

		hdr, err = getHeader(m)
		if err == io.EOF {
			err = nil
			if len(hdr) == 0 {
				break
			}
		}
		if err != nil {
			goto fin
		}

		if hdr == "\n" {
			// конец заголовка
			_, err = fh.WriteString(hdr)
			if err != nil {
				goto fin
			}
			break
		}

		if firstRecv && strings.HasPrefix(hdr, recvHdr) {

			sum := fmt.Sprintf("%x", sha256.Sum224([]byte(nospace(hdr))))

			_, err = fh.WriteString(strings.Join([]string{seenHdr, " ", sum, "\n"}, ""))
			if err != nil {
				goto fin
			}

			_, err = fh.WriteString(hdr)
			if err != nil {
				goto fin
			}

			firstRecv = false
			continue
		}

		if strings.HasPrefix(hdr, subjHdr) {

			_, err = fh.WriteString(strings.Join([]string{subjHdr, " ", subject, "\n"}, ""))
			if err != nil {
				goto fin
			}

			continue
		}

		_, err = fh.WriteString(hdr)
		if err != nil {
			goto fin
		}
	}

	for {
		line, err = m.ReadSlice('\n')
		if err == io.EOF {
			err = nil
			break
		}
		if err != nil {
			goto fin
		}

		_, err = fh.Write(line)
		if err != nil {
			goto fin
		}
	}

	if err = fh.Close(); err != nil {
		goto fin
	}

	err = os.Rename(filetemp, filename)

fin:
	if err != nil {
		Failure(seq, qid, err)
	} else {
		Discard(seq)
	}
}

func getHeader(m *bufio.Reader) (hdr string, err error) {

	var c byte
	var line []byte

	var b strings.Builder
	b.Grow(384)

	for {
		c, err = m.ReadByte()
		if err == io.EOF {
			if c == 0 {
				break
			} else {
				err = nil
			}
		}
		if err != nil {
			return
		}

		if b.Len() == 0 {

			if c == ' ' || c == '\t' {
				err = m.UnreadByte()
				if err != nil {
					return
				}
				err = fmt.Errorf("bad header")
				return

			} else if c == '\n' {

				b.WriteByte(c)
				break

			} else {

				b.WriteByte(c)

				line, err = m.ReadSlice('\n')
				if err == io.EOF {
					err = nil
				}
				if err != nil {
					return
				}

				b.Write(line)
			}

		} else {

			if c == ' ' || c == '\t' {

				b.WriteByte(c)

				line, err = m.ReadSlice('\n')
				if err == io.EOF {
					err = nil
				}
				if err != nil {
					return
				}

				b.Write(line)

			} else {
				err = m.UnreadByte()
				if err != nil {
					return
				}
				break
			}
		}
	}

	hdr = b.String()

	return
}

func isSeen(m *bufio.Reader) (seen bool, err error) {

	var found bool
	var seenSum string
	var hdr string

	for {

		hdr, err = getHeader(m)
		if err == io.EOF {
			err = nil
			if len(hdr) == 0 {
				break
			}
		}
		if err != nil {
			return
		}

		if hdr == "\n" {
			// конец заголовка
			break
		}

		if !found {

			if seenSum, found = strings.CutPrefix(hdr, seenHdr); found {
				seenSum = strings.TrimSpace(seenSum)
			}

		} else if strings.HasPrefix(hdr, recvHdr) {

			sum := fmt.Sprintf("%x", sha256.Sum224([]byte(nospace(hdr))))
			if seenSum == sum {
				seen = true
			}

			break
		}
	}

	return
}

func nospace(s string) string {

	var b strings.Builder
	b.Grow(len(s))

	for _, c := range s {
		if !unicode.IsSpace(c) {
			b.WriteRune(c)
		}
	}

	return b.String()
}

func replaceSpecChars(msg string) string {

	var sb strings.Builder
	sb.Grow(len(msg) + 128)

	for _, symbol := range msg {

		switch symbol {
		case rune('\\'):
			// replace \ -> \\   (CGP backslash)
			sb.WriteString("\\\\")

		case 0x0000:
			fallthrough
		case rune('\r'):
			continue

		case rune('\n'):
			// replace \n -> \\e (CGP End-of-Line)
			sb.WriteString("\\e")

		case rune('\t'):
			// replace \t -> \\t (CGP Tab)
			sb.WriteString("\\t")

		case rune('"'):
			// replace \" -> \\" (CGP quote)
			sb.WriteString("\\\"")

		default:
			sb.WriteRune(symbol)
		}
	}

	return sb.String()
}

func setMainDomain() (err error) {

	h, err := os.Open("Settings/Main.settings")
	if err != nil {
		return
	}
	defer h.Close()

	var line []byte

	for m := bufio.NewReader(h); ; {

		line, err = m.ReadSlice('\n')
		if err != nil {
			return
		}

		if s := reMD.FindAllStringSubmatch(string(line), -1); s != nil {
			MainDomain = s[0][1]
			break
		}
	}

	return
}

func uniqueNonEmptyElementsOf(s []string) []string {

	unique := make(map[string]bool, len(s))
	us := make([]string, len(unique))

	for _, elem := range s {
		if len(elem) != 0 {
			if !unique[elem] {
				us = append(us, elem)
				unique[elem] = true
			}
		}
	}

	return us
}
