package cgp

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

func Message(filename *string) (from string, rcpts []string, ip string, qid int, body []byte, err error) {

	qid, err = strconv.Atoi((*filename)[strings.LastIndexByte(*filename, '/')+1 : strings.LastIndexByte(*filename, '.')])
	if err != nil {
		return
	}

	h, err := os.Open(*filename)
	if err != nil {
		return
	}
	defer h.Close()

	var line []byte
	var pos int64

finalize:
	for m := bufio.NewReader(h); ; {
		line, err = m.ReadSlice('\n')
		if err != nil {
			return
		}

		pos += int64(len(line))

		if string(line) == "\n" {
			break finalize
		}

		switch line[0] {
		case 'P':
			from = string(line[strings.IndexByte(string(line), '<') : strings.IndexByte(string(line), '>')+1])

		case 'R':
			rcpts = append(rcpts, string(line[strings.IndexByte(string(line), '<'):strings.IndexByte(string(line), '>')+1]))

		case 'S':
			ip = string(line[strings.IndexByte(string(line), '[')+1 : strings.IndexByte(string(line), ']')])
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
		err = fmt.Errorf("cgp.Message() error: from='%s', len(to)=%d, ip='%s', size=%d/%d", from, len(rcpts), ip, len(body), n)
	}

	return
}

func Putline(format string, a ...interface{}) {
	s := fmt.Sprintf(format, a...)
	syscall.Write(int(os.Stdout.Fd()), []byte(s))
}

func ReplaceSpecChars(msgo *string) *string {

	var msgn string

	for _, symbol := range *msgo {

		switch symbol {
		case rune('\\'):
			// replace \ -> \\   (CGP backslash)
			msgn += "\\\\"

		case 0x0000:
			fallthrough
		case rune('\r'):
			continue

		case rune('\n'):
			// replace \n -> \\e (CGP End-of-Line)
			msgn += "\\e"

		case rune('\t'):
			// replace \t -> \\t (CGP Tab)
			msgn += "\\t"

		case rune('"'):
			// replace \" -> \\" (CGP quote)
			msgn += "\\\""

		default:
			msgn += string(symbol)
		}
	}

	return &msgn
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
