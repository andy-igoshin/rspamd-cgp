package cgp

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"syscall"
)

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

func Message(filename string) (from string, rcpts []string, auth string, ip string, qid int, body []byte, err error) {

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

	for m := bufio.NewReader(h); ; {

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

	rcpts = uniqueNonEmptyElementsOf(rcpts)

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
				Putline("%d %s DISCARD\n", seq, strings.Join(mirrorTo, " "))
			} else {
				Putline("%d %s ADDHEADER \"%s\" OK\n", seq, strings.Join(mirrorTo, " "), hdrs)
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

func Putline(format string, a ...interface{}) {
	s := fmt.Sprintf(format, a...)
	syscall.Write(int(os.Stdout.Fd()), []byte(s))
}

func Reject(seq int) {
	Putline("%d REJECT Try again later\n", seq)
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
