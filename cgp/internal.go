package cgp

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"git.vsu.ru/ai/rspamd-cgp/utils"
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

func getHeader(m *bufio.Reader) (hdr string, err error) {

	var c byte
	var line []byte

	var b strings.Builder
	b.Grow(384)

	for {
		c, err = m.ReadByte()
		if err != nil {
			if err == io.EOF {
				if c == 0 {
					break
				} else {
					err = nil
				}
			} else {
				return
			}
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
				if err != nil {
					if err == io.EOF {
						err = nil
					} else {
						return
					}
				}

				b.Write(line)
			}

		} else {

			if c == ' ' || c == '\t' {

				b.WriteByte(c)

				line, err = m.ReadSlice('\n')
				if err != nil {
					if err == io.EOF {
						err = nil
					} else {
						return
					}
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

func getHelo(body []byte) (helo string) {

	var hdr string
	var err error

	m := bufio.NewReader(bytes.NewReader(body))

	for {

		hdr, err = m.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				err = nil
				if len(hdr) == 0 {
					break
				}
			} else {
				return
			}
		}

		if hdr == "\n" {
			// конец заголовка
			break
		}

		if strings.HasPrefix(hdr, recvHdr) {
			if s := reHELO1.FindAllStringSubmatch(hdr, -1); s != nil {
				helo = s[0][1]
			} else if s := reHELO2.FindAllStringSubmatch(hdr, -1); s != nil {
				helo = s[0][1]
			}
			break
		}
	}

	return
}

func isSeen(m *bufio.Reader) (seen bool, err error) {

	var found bool
	var seenSum string
	var hdr string

	for {

		hdr, err = getHeader(m)
		if err != nil {
			if err == io.EOF {
				err = nil
				if len(hdr) == 0 {
					break
				}
			} else {
				return
			}
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

			bs := sha256.Sum224([]byte(utils.NoSpace(hdr)))
			sum := hex.EncodeToString(bs[:])
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
		if err != nil {
			if err == io.EOF {
				err = nil
				if len(hdr) == 0 {
					break
				}
			} else {
				return
			}
		}

		if hdr == "\n" {
			// конец заголовка
			break
		}

		if strings.HasPrefix(hdr, recvHdr) {
			bs := sha256.Sum224([]byte(utils.NoSpace(hdr)))
			seenhdr = seenHdr + " " + hex.EncodeToString(bs[:])
			break
		}
	}

	return
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
