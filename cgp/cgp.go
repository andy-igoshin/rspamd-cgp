package cgp

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"git.vsu.ru/ai/rspamd-cgp/utils"
)

const recvHdr = "Received:"
const seenHdr = "X-Rspamd-Seen:"
const subjHdr = "Subject:"
const submitDir = "Submitted"

var reHELO1 *regexp.Regexp
var reHELO2 *regexp.Regexp
var reMD *regexp.Regexp
var reSELF *regexp.Regexp
var reSMTP *regexp.Regexp
var protocol int

func init() {
	// Received: from muus52.sndsy.ru ([185.235.30.52] verified)
	reHELO1 = regexp.MustCompile(`^Received: from (\S+) \(.* ?\[\S+\] verified\)`)
	// Received: from [10.19.5.40] (account edu@vsu.ru HELO edu.vsu.ru)
	reHELO2 = regexp.MustCompile(`^Received: from \[\S+\] \(.*(?: ?HELO (\S+))\)`)
	reMD = regexp.MustCompile(`^\s+DomainName\s+=\s+([^;]+);`)
	reSELF = regexp.MustCompile(`^S (?:<([^>]+)> )?(ALARM|DSN|GROUP|ICAL|LIST|LSTM|LSTO|MDN|PBX|PIPE|RULE|WEBUSER) \[0\.0\.0\.0\]`)
	reSMTP = regexp.MustCompile(`^S (?:<([^>]+)> )?(?:SMTP|HTTPU?|AIRSYNC|IMAP|RPOP|XIMSS) \[([0-9a-f.:]+)\]`)
}

func AddHeader(seq int, headers []string) {

	hdrs := replaceSpecChars(strings.Join(headers, "\n"))

	if protocol >= 4 {
		Putline("%d ADDHEADER \"%s\" OK\n", seq, hdrs)
	} else {
		Putline("%d ADDHEADER \"%s\"\n", seq, hdrs)
	}
}

func AddHeaderWithMirrorTo(seq int, qid int, to []string, discard bool, headers []string,
	body []byte, outbound bool) {

	if !outbound || len(to) > 0 {
		seenHdr, err := makeSeen(body)
		if err != nil {
			Failure(seq, qid, err)
			return
		}
		headers = append(headers, seenHdr)
	}

	hdrs := replaceSpecChars(strings.Join(headers, "\n"))

	if protocol >= 4 {

		if len(to) > 0 {
			mirrorTo := make([]string, 0, len(to))
			for _, m := range to {
				mirrorTo = append(mirrorTo, "MIRRORTO \""+m+"\"")
			}

			if discard {
				Putline("%d ADDHEADER \"%s\" %s DISCARD\n", seq, hdrs, strings.Join(mirrorTo, " "))
			} else {
				Putline("%d ADDHEADER \"%s\" %s OK\n", seq, hdrs, strings.Join(mirrorTo, " "))
			}

		} else {
			if discard {
				Putline("%d ADDHEADER \"%s\" DISCARD\n", seq, hdrs)
			} else {
				Putline("%d ADDHEADER \"%s\" OK\n", seq, hdrs)
			}
		}

	} else {
		Putline("%d ADDHEADER \"%s\"\n", seq, hdrs)
	}
}

func Discard(seq int, qid int, from string, rcpts []string) {
	Putline("* %d [%d]: Action: discard; from %s, rcpts %s\n", seq, qid, from, strings.Join(rcpts, ","))
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

func MainDomain() (domain string, err error) {

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
			domain = s[0][1]
			break
		}
	}

	return
}

func Message(filename string) (from string, rcpts []string, auth string, ip string, helo string,
	hostname string, qid int, body []byte, seen bool, err error) {

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
				hostname = getHostname(ip)
			} else if s := reSELF.FindAllStringSubmatch(string(line), -1); s != nil {
				if len(s[0][1]) > 0 {
					auth = s[0][1]
				} else {
					auth = s[0][2] + "@trusted"
				}
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

	helo = getHelo(body)

	rcpts = utils.UniqueSliceElementsNonEmpty(rcpts)

	if from == "" || len(rcpts) == 0 || n < len(body) {
		err = fmt.Errorf("cgp.Message() error: from='%s', len(to)=%d, auth='%s' ip='%s', size=%d/%d", from, len(rcpts), auth, ip, len(body), n)
	}

	return
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

func RewriteSubject(seq int, headers []string, subject string, qid int, from string, rcpts []string, body []byte) (err error) {

	var firstRecv bool = true
	var m *bufio.Reader
	var hdr string
	var pos int = 0

	filename := submitDir + "/" + strconv.Itoa(qid) + "rs.sub"
	filetemp := strings.Replace(filename, "sub", "tmp", 1)

	fh, err := os.Create(filetemp)
	if err != nil {
		goto fin
	}
	defer fh.Close()

	_, err = fh.WriteString("Return-Path: " + from + "\n")
	if err != nil {
		goto fin
	}

	for _, rcpt := range rcpts {
		_, err = fh.WriteString("Envelope-To: " + rcpt + "\n")
		if err != nil {
			goto fin
		}
	}

	_, err = fh.WriteString(strings.Join(headers, "\n") + "\n")
	if err != nil {
		goto fin
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

		pos += len(hdr)

		if hdr == "\n" {
			// конец RFC5322 заголовка
			_, err = fh.WriteString(hdr)
			if err != nil {
				goto fin
			}
			break
		}

		if firstRecv && strings.HasPrefix(hdr, recvHdr) {

			bs := sha256.Sum224([]byte(utils.NoSpace(hdr)))
			sum := hex.EncodeToString(bs[:])

			_, err = fh.WriteString(seenHdr + " " + sum + "\n")
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

			_, err = fh.WriteString(subjHdr + " " + subject + "\n")
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

	_, err = fh.Write(body[pos:])
	if err != nil {
		goto fin
	}

	if err = fh.Close(); err != nil {
		goto fin
	}

	err = os.Rename(filetemp, filename)

fin:
	return
}
