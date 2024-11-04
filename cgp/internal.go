package cgp

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"strings"
	"unicode"
)

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
			// конец RFC5322 заголовка
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

func makeSeen(body []byte) (seenhdr string, err error) {

	var hdr string

	m := bufio.NewReader(bytes.NewReader(body))

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
			break
		}

		if strings.HasPrefix(hdr, recvHdr) {
			seenhdr = fmt.Sprintf("%s %x", seenHdr, sha256.Sum224([]byte(nospace(hdr))))
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
