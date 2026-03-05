package cgp

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"strconv"
	"sync"
	"syscall"
)

type Appender interface {
    Append([]byte) []byte
}

const (
	submitDir = "Submitted"
)

var (
	protocol int = 4
	stdoutFd int
)

var bufferPool = sync.Pool{
	New: func() any { return bytes.NewBuffer(make([]byte, 0, 4096)) },
}

func AddHeader(seq int, headers []string) {
	buf := bufferPool.Get().(*bytes.Buffer)
	defer putBuffer(buf)

	buf.WriteString(strconv.Itoa(seq))
	buf.WriteString(" ADDHEADER \"")

	for i, h := range headers {
		replaceSpecCharsBuf(buf, h)
		if i < len(headers)-1 {
			buf.WriteString("\\e")
		}
	}

	buf.WriteString("\" OK")

	res := buf.Bytes()
	length := len(res)

	if length > 4096 || (length == 4096 && res[length-1] != '\n') {
		Failure(seq, 0, fmt.Errorf("AddHeader: result exceeds 4k limit"))
		return
	}

	if length > 0 && res[length-1] != '\n' {
		buf.WriteByte('\n')
		res = buf.Bytes()
	}

	syscall.Write(stdoutFd, res)
}

func Discard(seq int) {
	var buf [64]byte
	b := strconv.AppendInt(buf[:0], int64(seq), 10)
	b = append(b, " DISCARD\n"...)
	syscall.Write(stdoutFd, b)
}

func Failure(seq, qid int, err error) {
	var buf [512]byte
	b := buf[:0]

	b = append(b, "* "...)
	b = strconv.AppendInt(b, int64(seq), 10)
	b = append(b, " ["...)
	b = strconv.AppendInt(b, int64(qid), 10)
	b = append(b, "]: "...)
	if err != nil {
		b = append(b, err.Error()...)
	} else {
		b = append(b, "unknown error"...)
	}

	length := len(b)
	if length > 0 && b[length-1] != '\n' {
		b = append(b, '\n')
	}
	syscall.Write(stdoutFd, b)

	b = buf[:0]
	b = strconv.AppendInt(b, int64(seq), 10)
	b = append(b, " FAILURE\n"...)
	syscall.Write(stdoutFd, b)
}

// InitStdoutFd инициализирует системный дескриптор для ответов серверу.
// Вызывать в самом начале main().
func InitStdoutFd() error {
	rawConn, err := os.Stdout.SyscallConn()
	if err != nil {
		return err
	}

	err = rawConn.Control(func(fd uintptr) {
		stdoutFd = int(fd)
	})

	if err != nil {
		return err
	}

	return nil
}

func Intf(seq int, ver string) {
	var buf [64]byte
	b := strconv.AppendInt(buf[:0], int64(seq), 10)
	b = append(b, " INTF "...)
	b = append(b, strconv.FormatInt(int64(protocol), 10)...)
	b = append(b, '\n')
	syscall.Write(stdoutFd, b)
}

func MainDomain() (string, error) {
	h, err := os.Open("Settings/Main.settings")
	if err != nil {
		return "", err
	}
	defer h.Close()

	rd := bufio.NewReader(h)
	key := []byte("DomainName")

	for {
		line, err := rd.ReadSlice('\n')
		if err != nil && err != io.EOF {
			return "", err
		}

		// Ищем вхождение DomainName
		idxKey := bytes.Index(line, key)
		if idxKey == -1 {
			if err == io.EOF {
				break
			}
			continue
		}

		// Проверяем, что перед ключом стоит разделитель (начало строки, пробел, { или ;)
		if idxKey > 0 {
			prev := line[idxKey-1]
			if prev != ' ' && prev != '\t' && prev != '{' && prev != ';' {
				if err == io.EOF {
					break
				}
				continue
			}
		}

		// Ищем '=' после ключа
		lineAfterKey := line[idxKey+len(key):]
		idxEq := bytes.IndexByte(lineAfterKey, '=')
		if idxEq == -1 {
			if err == io.EOF {
				break
			}
			continue
		}

		// Ищем ';' после '='
		idxSemi := bytes.IndexByte(lineAfterKey[idxEq:], ';')
		if idxSemi == -1 {
			if err == io.EOF {
				break
			}
			continue
		}

		// Извлекаем и чистим значение
		rawVal := lineAfterKey[idxEq+1 : idxEq+idxSemi]
		cleanVal := bytes.Trim(rawVal, " \t\r\n\"")

		if len(cleanVal) > 0 {
			return string(cleanVal), nil
		}

		if err == io.EOF {
			break
		}
	}

	return "", fmt.Errorf("DomainName not found in settings")
}

func MirrorTo(seq int, m *Message, to []string, headers []string, discard bool) {
	buf := bufferPool.Get().(*bytes.Buffer)
	defer putBuffer(buf)

	// SEQ [ADDHEADER "h1\eh2"] [MIRRORTO "rcpt"] {DISCARD|OK}
	buf.WriteString(strconv.Itoa(seq))

	if len(headers) > 0 {
		buf.WriteString(" ADDHEADER \"")
		for i, h := range headers {
			replaceSpecCharsBuf(buf, h)
			if i < len(headers)-1 {
				buf.WriteString("\\e")
			}
		}
		buf.WriteString("\"")
	}

	for _, rcpt := range to {
		buf.WriteString(" MIRRORTO \"")
		replaceSpecCharsBuf(buf, rcpt)
		buf.WriteString("\"")
	}

	if discard {
		buf.WriteString(" DISCARD")
	} else {
		buf.WriteString(" OK")
	}

	res := buf.Bytes()
	if len(res) > 4096 {
		Failure(seq, m.QID, fmt.Errorf("MirrorTo: result exceeds 4k limit (%d bytes)", len(res)))
		return
	}

	if len(res) > 0 && res[len(res)-1] != '\n' {
		buf.WriteByte('\n')
		res = buf.Bytes()
	}

	syscall.Write(stdoutFd, res)
}

func Ok(seq int) {
	var buf [64]byte
	b := strconv.AppendInt(buf[:0], int64(seq), 10)
	b = append(b, " OK\n"...)
	syscall.Write(stdoutFd, b)
}

func OkSeen(seq, qid int) {
	var buf [128]byte
	b := buf[:0]
	b = append(b, "* "...)
	b = strconv.AppendInt(b, int64(seq), 10)
	b = append(b, " ["...)
	b = strconv.AppendInt(b, int64(qid), 10)
	b = append(b, "]: Already seen by Rspamd\n"...)
	syscall.Write(stdoutFd, b)
	Ok(seq)
}

func Putline(a ...any) {
	var stackBuf [256]byte
	res := stackBuf[:0]

	for _, arg := range a {
		switch v := arg.(type) {
		case string:
			res = append(res, v...)
		case int:
			res = strconv.AppendInt(res, int64(v), 10)
		case int64:
			res = strconv.AppendInt(res, v, 10)
		case float64:
			res = strconv.AppendFloat(res, v, 'f', 2, 64)
		case Appender:
			res = v.Append(res)
		case float32:
			res = strconv.AppendFloat(res, float64(v), 'f', 2, 64)
		case error:
			if v != nil {
				res = append(res, v.Error()...)
			}
		case []byte:
			res = append(res, v...)
		default:
			res = append(res, fmt.Sprint(v)...)
		}
	}

	length := len(res)

	if length > 4096 || (length == 4096 && length > 0 && res[length-1] != '\n') {
		os.Stderr.WriteString("Putline: result exceeds 4k limit\n")
		return
	}

	if length > 0 && res[length-1] != '\n' {
		res = append(res, '\n')
	}

	syscall.Write(stdoutFd, res)
}

func Reject(seq int) {
	var buf [64]byte
	b := strconv.AppendInt(buf[:0], int64(seq), 10)
	b = append(b, " REJECT Try again later\n"...)
	syscall.Write(stdoutFd, b)
}
