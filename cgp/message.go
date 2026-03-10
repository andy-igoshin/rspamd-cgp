package cgp

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/cespare/xxhash/v2"

	"git.vsu.ru/ai/rspamd-cgp/utils"
)

type Message struct {
	File     *os.File
	QID      int
	From     string
	Rcpts    []string
	Auth     string
	IP       string
	Helo     string
	Hostname string

	HdrPos  int64 // Смещение до RFC заголовков (после конверта)
	BodyPos int64 // Смещение до RFC тела (после заголовков)
	Size    int64 // Общий размер файла

	seen        bool
	extReceived []byte
}

var (
	readerPool = sync.Pool{
		New: func() any { return bufio.NewReaderSize(nil, 4096) },
	}
	writerPool = sync.Pool{
		New: func() any { return bufio.NewWriterSize(nil, 4096) },
	}
)

var (
	bRecvHdr  = []byte("Received: ")
	bRecvFrom = []byte("Received: from ")
	bSeenHdr  = []byte("X-Rspamd-Seen: ")
	bSubjHdr  = []byte("Subject: ")
)

var (
	// Тип источника: 1 - Внешний (SMTP/HTTP...), 2 - Внутренний (RULE/LIST...)
	sourceModules = map[string]int{
		"SMTP": 1, "HTTP": 1, "HTTPU": 1, "AIRSYNC": 1, "IMAP": 1, "RPOP": 1, "XIMSS": 1,
		"ALARM": 2, "DSN": 2, "GROUP": 2, "ICAL": 2, "LIST": 2, "LSTM": 2, "LSTO": 2,
		"MDN": 2, "PBX": 2, "PIPE": 2, "RULE": 2, "WEBUSER": 2,
	}
)

func (m *Message) Close() error {
	return m.File.Close()
}

func (m *Message) IsSeen() bool {
	return m.seen
}

func (m *Message) MakeSeen() string {
	// Если внешних Received не найдено (внутреннее письмо),
	// возвращаем пустую строку, чтобы заголовок не добавлялся.
	if len(m.extReceived) == 0 {
		return ""
	}

	// bSeenHdr = []byte("X-Rspamd-Seen: ")
	// Собираем строку: имя заголовка + хеш от сохраненного оригинала
	return string(bSeenHdr) + hashReceived(m.extReceived)
}

func NewMessage(seq int, filename string) (*Message, error) {
	// 1. Извлечение QID из имени файла (например, 12345.msg -> 12345)
	start := strings.LastIndexByte(filename, '/') + 1
	end := strings.LastIndexByte(filename, '.')
	if end <= start {
		return nil, fmt.Errorf("invalid filename: %s", filename)
	}

	qid, err := strconv.Atoi(filename[start:end])
	if err != nil {
		return nil, fmt.Errorf("parse QID failed: %w", err)
	}

	// 2. Открытие файла оригинала
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}

	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}

	msg := &Message{
		File: f,
		QID:  qid,
		Size: fi.Size(),
	}

	// 3. Подготовка ридера из пула
	rd := getReader(f)
	defer putReader(rd)

	var pos int64

	// 4. Читаем Конверт (Envelope)
	for {
		line, err := rd.ReadSlice('\n')
		if err != nil {
			if err == io.EOF {
				err = fmt.Errorf("unexpected end of envelope")
			}
			f.Close()
			return nil, err
		}
		pos += int64(len(line))

		if isHeaderEnd(line) {
			break
		}

		// Парсинг параметров конверта
		switch line[0] {
		case 'P': // Return-Path
			if v, ok := extractAngle(line); ok {
				msg.From = v
			}
		case 'R': // Envelope-To
			if v, ok := extractAngle(line); ok {
				msg.Rcpts = append(msg.Rcpts, v)
			}
		case 'S': // Source/Interface info
			parseSource(seq, line, msg)
		}
	}
	msg.HdrPos = pos

	// 5. Разбор Заголовков (Headers)
	buf := bufferPool.Get().(*bytes.Buffer)
	defer putBuffer(buf)

	var (
		seenSum          string
		seenFound        bool
		seenProcessed    bool
		extReceivedSaved bool
	)

	for {
		buf.Reset()
		err := getHeader(rd, buf)
		hdr := buf.Bytes()

		if len(hdr) > 0 {
			pos += int64(len(hdr))

			if isHeaderEnd(hdr) {
				break
			}

			// А. Проверка существующей метки Seen (Прошлое)
			// Доверяем порядку: Метка -> (опционально не-Received) -> Первый Received
			if !seenProcessed {
				if !seenFound {
					if bytes.HasPrefix(hdr, bSeenHdr) {
						seenSum = string(bytes.TrimSpace(hdr[len(bSeenHdr):]))
						seenFound = true
					}
				} else if bytes.HasPrefix(hdr, bRecvHdr) {
					// Валидируем по первому же встречному Received
					if hashReceived(hdr) == seenSum {
						msg.seen = true
					}
					seenProcessed = true
				}
			}

			// Б. Идентификация точки входа (Будущее)
			// Нас интересует только первый внешний Received.
			if !extReceivedSaved && isExternal(hdr) {
				msg.extReceived = bytes.Clone(hdr)
				extReceivedSaved = true
				msg.Helo = getHelo(hdr)
			}
		}

		if err != nil {
			if err == io.EOF {
				break
			}
			f.Close()
			return nil, err
		}
	}

	msg.BodyPos = pos

	// Очистка списка получателей от теоретических дублей
	msg.Rcpts = utils.UniqueSliceElementsNonEmpty(msg.Rcpts)

	return msg, nil
}

func (m *Message) PrintMsgInfo() {
	fmt.Fprintln(os.Stderr, "from:    ", m.From)
	fmt.Fprintln(os.Stderr, "rcpts:   ", m.Rcpts)
	fmt.Fprintln(os.Stderr, "ip:      ", m.IP)
	fmt.Fprintln(os.Stderr, "helo:    ", m.Helo)
	fmt.Fprintln(os.Stderr, "hostname:", m.Hostname)
	fmt.Fprintln(os.Stderr, "qid:     ", m.QID)
	if len(m.Auth) > 0 {
		fmt.Fprintln(os.Stderr, "auth:    ", m.Auth)
	} else {
		fmt.Fprintln(os.Stderr, "auth:     not authenticated")
	}
	fmt.Fprintln(os.Stderr, "seen:    ", m.seen)
	fmt.Fprintln(os.Stderr, "")
}

func (m *Message) RewriteSubject(headers []string, subject string) (err error) {
	sQid := strconv.Itoa(m.QID)
	filetemp := submitDir + "/" + sQid + "rs.tmp"
	filename := submitDir + "/" + sQid + "rs.sub"

	fh, err := os.Create(filetemp)
	if err != nil {
		return fmt.Errorf("RewriteSubject: create tmp failed: %w", err)
	}

	w := getWriter(fh)
	success := false

	defer func() {
		if !success {
			putWriter(w)
			fh.Close()
			os.Remove(filetemp)
		}
	}()

	// 1. Формируем конверт (Submitted требует Return-Path и Envelope-To)
	w.WriteString("Return-Path: ")
	w.WriteString(m.From)
	w.WriteByte('\n')
	for _, r := range m.Rcpts {
		w.WriteString("Envelope-To: ")
		w.WriteString(r)
		w.WriteByte('\n')
	}

	// 2. Метаданные (Seen, Junk-Score, DKIM).
	for _, h := range headers {
		w.WriteString(h)
		w.WriteByte('\n')
	}

	// 3. Подготовка к чтению оригинальных заголовков
	if _, err = m.File.Seek(m.HdrPos, io.SeekStart); err != nil {
		return err
	}

	rd := getReader(m.File)
	defer putReader(rd)

	buf := bufferPool.Get().(*bytes.Buffer)
	defer putBuffer(buf)

	// 4. Цикл обработки заголовков: копируем всё, заменяя Subject
	for {
		buf.Reset()
		if err = getHeader(rd, buf); err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		hdr := buf.Bytes()

		if isHeaderEnd(hdr) {
			w.Write(hdr)
			break
		}

		// Заменяем оригинальный Subject на новый
		if bytes.HasPrefix(hdr, bSubjHdr) {
			w.Write(bSubjHdr)
			w.WriteString(subject)
			w.WriteByte('\n')
			continue
		}

		w.Write(hdr)
	}

	// 5. Перенос тела письма напрямую через io.Copy
	if _, err = m.File.Seek(m.BodyPos, io.SeekStart); err != nil {
		return err
	}
	if _, err = io.Copy(w, m.File); err != nil {
		return err
	}

	if err = w.Flush(); err != nil {
		return err
	}
	if err = fh.Close(); err != nil {
		return err
	}

	if err = os.Rename(filetemp, filename); err != nil {
		return err
	}

	success = true
	putWriter(w)
	return nil
}

func getReader(r io.Reader) *bufio.Reader {
	rd := readerPool.Get().(*bufio.Reader)
	rd.Reset(r)
	return rd
}

func getWriter(w io.Writer) *bufio.Writer {
	bw := writerPool.Get().(*bufio.Writer)
	bw.Reset(w)
	return bw
}

func hashReceived(b []byte) string {
	h := xxhash.New()

	start := 0
	for i := 0; i < len(b); i++ {
		// Нормализация: игнорируем пробелы, табы и переносы строк (folding)
		if b[i] <= 32 {
			if i > start {
				h.Write(b[start:i])
			}
			start = i + 1
		}
	}

	// Дописываем остаток, если он есть
	if start < len(b) {
		h.Write(b[start:])
	}

	// Результат — 64-битное число, приводим к hex (16 символов)
	return strconv.FormatUint(h.Sum64(), 16)
}

func isExternal(hdr []byte) bool {
	// 1. Проверяем полный префикс.
	if !bytes.HasPrefix(hdr, bRecvFrom) {
		return false
	}

	// 2. Смещаемся за "Received: from "
	fromVal := hdr[len(bRecvFrom):]
	if len(fromVal) == 0 {
		return false
	}

	// 3. Быстрый чек на IP в скобках [IP] (SMTP/Web)
	if fromVal[0] == '[' {
		return true
	}

	// 4. Ищем границу идентификатора (до первого пробела)
	firstSpace := bytes.IndexByte(fromVal, ' ')
	if firstSpace == -1 {
		firstSpace = len(fromVal)
	}
	firstWord := fromVal[:firstSpace]

	// 5. Проверка на Email (GROUP/RULE).
	// Если во входном идентификаторе нет '@', это сетевой хост.
	return len(firstWord) > 0 && !bytes.Contains(firstWord, []byte("@"))
}

func isHeaderEnd(hdr []byte) bool {
	return len(hdr) == 1 && hdr[0] == '\n' ||
		(len(hdr) == 2 && hdr[0] == '\r' && hdr[1] == '\n')
}

/*
		внешние источники: SMTP|HTTPU?|AIRSYNC|IMAP|RPOP|XIMSS
		S <test@domain.name> AIRSYNC [83.139.170.75]
		S <test@domain.name> HTTP [46.72.226.199]
		S SMTP [130.193.65.125]
		S <test@domain.name> SMTP [2001:67c:418:2020::21]
		S RPOP [81.19.77.161]

		внутренние источники: ALARM|DSN|GROUP|ICAL|LIST|LSTM|LSTO|MDN|PBX|PIPE|RULE|WEBUSER
		S DSN [0.0.0.0]
	 	S GROUP [0.0.0.0]
	 	S LIST [0.0.0.0]
		S LSTM [0.0.0.0]
		S <test@domain.name> MDN [0.0.0.0]
		S PIPE [0.0.0.0]
		S <postmaster@domain.name> RULE [0.0.0.0]
*/
func parseSource(seq int, line []byte, msg *Message) {
	// Строка вида: S [<auth> ]MODULE [IP]
	data := bytes.TrimSpace(line[1:])
	if len(data) == 0 {
		return
	}

	var auth string
	// 1. Извлекаем <auth>, если он присутствует
	if data[0] == '<' {
		endAuth := bytes.IndexByte(data, '>')
		if endAuth != -1 {
			auth = string(data[1:endAuth])
			data = bytes.TrimSpace(data[endAuth+1:])
		}
	}

	// 2. Ищем IP в квадратных скобках в конце строки
	openBracket := bytes.LastIndexByte(data, '[')
	closeBracket := bytes.LastIndexByte(data, ']')

	if openBracket == -1 || closeBracket == -1 || closeBracket <= openBracket {
		Putline("* ", seq, " [", msg.QID, "]: unknown S-line format: ", utils.Bytes2string(line))
		return
	}

	moduleBytes := bytes.TrimSpace(data[:openBracket])
	ipBytes := data[openBracket+1 : closeBracket]

	mType, known := sourceModules[utils.Bytes2string(moduleBytes)]

	// 3. Заполнение структуры
	if known && mType == 2 && bytes.Equal(ipBytes, []byte("0.0.0.0")) {
		// Внутренний источник (trusted)
		if auth != "" {
			msg.Auth = auth
		} else {
			msg.Auth = string(moduleBytes) + "@trusted"
		}
		msg.IP = "127.2.4.7"
	} else if known && mType == 1 {
		// Внешний источник (SMTP, и т.д.)
		msg.Auth = auth
		msg.IP = string(ipBytes)
		msg.Hostname = getHostname(msg.IP)
	} else {
		Putline("* ", seq, " [", msg.QID, "]: unknown or mismatched module in S-line: ", string(line))
	}
}

func putReader(rd *bufio.Reader) {
	rd.Reset(nil)
	readerPool.Put(rd)
}

func putWriter(wr *bufio.Writer) {
	wr.Reset(nil)
	writerPool.Put(wr)
}
