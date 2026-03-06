package cgp

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

func extractAngle(line []byte) (string, bool) {
	s := strings.IndexByte(string(line), '<')
	if s < 0 {
		return "", false
	}
	e := strings.IndexByte(string(line[s:]), '>')
	if e < 0 {
		return "", false
	}
	return string(line[s : s+e+1]), true
}

func getHeader(m *bufio.Reader, buf *bytes.Buffer) error {
	for {
		line, err := m.ReadSlice('\n')
		if err != nil && err != bufio.ErrBufferFull {
			if len(line) > 0 {
				buf.Write(line)
			}
			return err
		}

		buf.Write(line)

		if err == bufio.ErrBufferFull {
			if buf.Len() > 64*1024 {
				return fmt.Errorf("header too long")
			}
			continue
		}

		if isHeaderEnd(line) {
			return nil
		}

		next, err := m.Peek(1)
		if err != nil {
			return err
		}

		if next[0] != ' ' && next[0] != '\t' {
			return nil
		}
	}
}

func getHelo(hdr []byte) string {
	if !bytes.HasPrefix(hdr, []byte("Received: from ")) {
		return ""
	}

	data := hdr[15:]

	// Received: from muus52.sndsy.ru ([185.235.30.52] verified)
	if idxOpen := bytes.Index(data, []byte(" ([")); idxOpen > 0 {
		if bytes.Contains(data[idxOpen:], []byte(" verified)")) {
			return string(bytes.TrimSpace(data[:idxOpen]))
		}
	}

	// Received: from [77.83.39.182] (HELO poseidonms.com)
	// Received: from [10.19.5.40] (account test@domain.name HELO test.domain.name)
	if idxHelo := bytes.Index(data, []byte("HELO ")); idxHelo > 0 {
		prevChar := data[idxHelo-1]
		if prevChar == ' ' || prevChar == '(' {
			remaining := data[idxHelo+5:]
			if end := bytes.IndexByte(remaining, ')'); end != -1 {
				return string(bytes.TrimSpace(remaining[:end]))
			}
		}
	}

	return ""
}

func isSeen(m *bufio.Reader) (seen bool, err error) {
	buf := bufferPool.Get().(*bytes.Buffer)
	defer putBuffer(buf)

	var found bool
	var seenSum []byte

	for {
		err = getHeader(m, buf)
		if err != nil {
			if err == io.EOF {
				err = nil
			}
			return
		}

		hdr := buf.Bytes()

		if len(hdr) == 0 || (len(hdr) == 1 && hdr[0] == '\n') ||
			(len(hdr) == 2 && hdr[0] == '\r' && hdr[1] == '\n') {
			break
		}

		if !found {
			if bytes.HasPrefix(hdr, bSeenHdr) {
				val := bytes.TrimSpace(hdr[len(bSeenHdr):])
				seenSum = make([]byte, len(val))
				copy(seenSum, val)
				found = true
			}
		} else if bytes.HasPrefix(hdr, bRecvHdr) {
			if hashReceived(hdr) == string(seenSum) {
				seen = true
				break
			}
		}
	}
	return
}

func putBuffer(buf *bytes.Buffer) {
	if buf.Cap() > 4096 {
		return
	}
	buf.Reset()
	bufferPool.Put(buf)
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

func replaceSpecCharsBuf(buf *bytes.Buffer, s string) {
	for _, r := range s {
		switch r {
		case '\\':
			buf.WriteString("\\\\")
		case '\n':
			buf.WriteString("\\e")
		case '\t':
			buf.WriteString("\\t")
		case '"':
			buf.WriteString("\\\"")
		case '\r', 0x00:
			continue
		default:
			if r < utf8.RuneSelf {
				buf.WriteByte(byte(r))
			} else {
				buf.WriteRune(r)
			}
		}
	}
}
