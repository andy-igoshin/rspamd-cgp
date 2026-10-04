package rspamc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"git.vsu.ru/ai/rspamd-cgp/cgp"
	"git.vsu.ru/ai/rspamd-cgp/config"
	"git.vsu.ru/ai/rspamd-cgp/utils"
)

const (
	headerCase  string = "X-Rspamd-Case: "
	headerJunkG string = "X-Junk-Score: [XX]"
	headerJunkA string = "X-Junk-Score: [XXXX]"
	headerJunkR string = "X-Junk-Score: [XXXXXXXXXX]"
)

func filterLocalRcpts(rcpts []string, res *RspamdResponse) []string {
	filtered := make([]string, 0, len(rcpts))

	if res.Symbols == nil {
		return filtered
	}

	v, ok := res.Symbols["RCPTS_DOMAINS_LOCAL"]
	if !ok || v == nil || len(v.Options) == 0 {
		return filtered
	}

	for _, rcpt := range rcpts {
		at := strings.IndexByte(rcpt, '@')
		if at < 0 {
			continue
		}

		rcptDomain := rcpt[at+1:]
		for _, domain := range v.Options {
			if strings.EqualFold(rcptDomain, domain) {
				filtered = append(filtered, rcpt)
				break
			}
		}
	}
	return filtered
}

func isOpAccept(dir config.Direction, outbound bool) bool {
	switch dir {
	case config.DirBoth:
		return true
	case config.DirOut:
		return outbound
	case config.DirIn:
		return !outbound
	default:
		return false
	}
}

func makeHeaders(res *RspamdResponse) (headers []string) {
	if res.DKIMSignature != "" {
		headers = append(headers, "DKIM-Signature: "+res.DKIMSignature)
	}

	if res.Milter != nil && res.Milter.AddHeaders != nil {
		for h, vh := range res.Milter.AddHeaders {
			if vh.Value != "" {
				headers = append(headers, h+": "+vh.Value)
			}
		}
	}

	return
}

func makeHeadersOutbound(res *RspamdResponse) (headers []string) {
	if res.DKIMSignature != "" {
		headers = append(headers, "DKIM-Signature: "+res.DKIMSignature)
	}
	return
}

func makeOpSum(res *RspamdResponse, action string) (*config.Operation, string, string, string) {
	var casea []string
	var desca []string
	var opsum *config.Operation

	// Обработка Action
	if op, ok := config.Action(action); ok {
		if isOpAccept(op.Direction, config.Outbound()) {
			if opsum == nil {
				opsum = new(config.Operation)
			}
			opsum.Discard = op.Discard
			opsum.MirrorTo = op.MirrorTo
			opsum.NotifyRcpts = op.NotifyRcpts
			opsum.NotifyTo = op.NotifyTo
			casea = append(casea, action)

			if len(op.Description) > 0 {
				desca = append(desca, action+": "+op.Description)
			} else {
				desca = append(desca, action)
			}

			if config.Debug() {
				printSelectedOp("Action", action, op.Direction, config.Outbound())
			}
		}
	}

	// Обработка Symbols
	if res.Symbols != nil {
		for symbol, op := range config.Symbols() {
			if isOpAccept(op.Direction, config.Outbound()) {
				if v, ok := res.Symbols[symbol]; ok && v != nil {
					if opsum == nil {
						opsum = new(config.Operation)
					}
					opsum.Discard = opsum.Discard || op.Discard
					opsum.MirrorTo = append(opsum.MirrorTo, op.MirrorTo...)
					opsum.NotifyRcpts = opsum.NotifyRcpts || op.NotifyRcpts
					opsum.NotifyTo = append(opsum.NotifyTo, op.NotifyTo...)
					casea = append(casea, symbol)

					if len(op.Description) > 0 {
						desca = append(desca, symbol+": "+op.Description)
					} else if v.Description != "" {
						desca = append(desca, symbol+": "+v.Description)
					} else {
						desca = append(desca, symbol)
					}

					if config.Debug() {
						printSelectedOp("Symbol", symbol, op.Direction, config.Outbound())
					}
				}
			}
		}
	}

	if len(casea) > 0 {
		var sb strings.Builder
		sb.Grow(256)

		// Формирования casework
		sb.WriteString("discard ")
		sb.WriteString(strconv.FormatBool(opsum.Discard))
		sb.WriteString("; notifyrcpts ")
		sb.WriteString(strconv.FormatBool(opsum.NotifyRcpts))

		if len(opsum.MirrorTo) > 0 {
			opsum.MirrorTo = utils.UniqueSliceElementsNonEmpty(opsum.MirrorTo)
			sb.WriteString("; mirrorto ")
			sb.WriteString(strings.Join(opsum.MirrorTo, ","))
		}

		if len(opsum.NotifyTo) > 0 {
			opsum.NotifyTo = utils.UniqueSliceElementsNonEmpty(opsum.NotifyTo)
			sb.WriteString("; notifyto ")
			sb.WriteString(strings.Join(opsum.NotifyTo, ","))
		}

		return opsum, strings.Join(casea, ","), sb.String(), strings.Join(desca, "\n")
	}

	return nil, "", "", ""
}

func printSelectedOp(optype, opname string, dir config.Direction, outbound bool) {

	if outbound {
		fmt.Fprintf(os.Stderr, "%s '%s' selected for outbound flow: direction %s\n", optype, opname, dir.String())
	} else {
		fmt.Fprintf(os.Stderr, "%s '%s' selected for inbound flow: direction %s\n", optype, opname, dir.String())
	}
}

func printResponse(debugBuf *bytes.Buffer) {
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, debugBuf.Bytes(), "", "  "); err == nil {
		os.Stderr.Write(pretty.Bytes())
		os.Stderr.Write([]byte("\n"))
	}
}

// procAction обрабатывает вердикт Rspamd согласно BNF:
// SEQ [ADDHEADER "h"] [MIRRORTO "a"] {OK|DISCARD}
func procAction(seq int, msg *cgp.Message, opsum *config.Operation, res *RspamdResponse,
	headers []string, hci, notifyfrom, desc string, t int) {

	var actualMirror []string
	var discard bool

	// Уведомления
	procNotifications(seq, msg, opsum, res, hci, notifyfrom, desc)

	// Определение намерения
	if opsum != nil {
		discard = opsum.Discard
		actualMirror = opsum.MirrorTo
	} else {
		discard = (t == 2)
	}

	// Валидация MirrorTo (Seen tag)
	if len(actualMirror) > 0 {
		if seenHdr := msg.MakeSeen(); seenHdr != "" {
			headers = append(headers, seenHdr)
		} else {
			cgp.Putline("* ", seq, " [", msg.QID, "]: warning: MirrorTo skipped (no Seen tag)")
			actualMirror = nil
		}
	}

	// Оптимизация ADDHEADER
	if discard && len(actualMirror) == 0 {
		headers = nil
	}

	// Финальный ответ
	cgp.MirrorTo(seq, msg, actualMirror, headers, discard)
}

// procActionRS обрабатывает Rewrite Subject через создание .sub файла в Submitted/
func procActionRS(seq int, msg *cgp.Message, opsum *config.Operation, res *RspamdResponse,
	headers []string, hci, notifyfrom, desc string) {

	// Уведомления
	procNotifications(seq, msg, opsum, res, hci, notifyfrom, desc)

	seenHdr := msg.MakeSeen()

	// FALLBACK: Метки нет — НИКАКИХ MIRRORTO.
	// Мы только модифицируем текущее письмо (ADDHEADER) и отдаем OK.
	if seenHdr == "" {
		cgp.Putline("* ", seq, " [", msg.QID, "]: warning: RewriteSubject fallback (no Seen tag). MirrorTo suppressed.")

		// Добавляем заголовок с предложенной темой к оригиналу
		headers = append(headers, "X-Spam-Subject: "+res.Subject)

		// Явный вызов метода, не имеющего отношения к дублированию писем
		cgp.AddHeader(seq, headers)
		return
	}

	// ШТАТНЫЙ РЕЖИМ: Метка есть, можем безопасно делать MIRRORTO
	headers = append(headers, seenHdr)

	// Пишем новый файл в Submitted/
	if err := msg.RewriteSubject(headers, res.Subject); err != nil {
		cgp.Failure(seq, msg.QID, fmt.Errorf("RewriteSubject failed: %v", err))
		return
	}

	// Удаляем оригинал.
	// Если в opsum был MirrorTo, он уйдет в этой же строке (SEQ [MIRRORTO] DISCARD).
	var actualMirror []string
	if opsum != nil {
		actualMirror = opsum.MirrorTo
	}

	// Финальный ответ
	cgp.MirrorTo(seq, msg, actualMirror, headers, true)
}

func procActionSwitch(seq int, msg *cgp.Message, opsum *config.Operation, res *RspamdResponse, headers []string, hci, action, desc string) {
	outbound := config.Outbound()
	notifyFrom := config.NotifyFrom()

	switch action {
	case "no action":
		procAction(seq, msg, opsum, res, headers, hci, notifyFrom, desc, 0)

	case "discard":
		if !outbound {
			headers = append(headers, headerJunkR)
		}
		procAction(seq, msg, opsum, res, headers, hci, notifyFrom, desc, 2)

	case "quarantine", "reject":
		if !outbound {
			headers = append(headers, headerJunkR)
		}
		procAction(seq, msg, opsum, res, headers, hci, notifyFrom, desc, 1)

	case "rewrite subject":
		if res.Subject != "" {
			procActionRS(seq, msg, opsum, res, headers, hci, notifyFrom, desc)
		} else {
			if !outbound {
				headers = append(headers, headerJunkA)
			}
			procAction(seq, msg, opsum, res, headers, hci, notifyFrom, desc, 1)
		}

	case "add header":
		if !outbound {
			headers = append(headers, headerJunkA)
		}
		procAction(seq, msg, opsum, res, headers, hci, notifyFrom, desc, 1)

	case "greylist", "soft reject":
		if !outbound {
			headers = append(headers, headerJunkG)
		}
		procAction(seq, msg, opsum, res, headers, hci, notifyFrom, desc, 1)

	default:
		cgp.Failure(seq, msg.QID, fmt.Errorf("Unknown action: %v", action))
	}
}

func procNotifications(seq int, msg *cgp.Message, opsum *config.Operation, res *RspamdResponse, hci, notifyfrom, desc string) {
	if opsum == nil || (!opsum.NotifyRcpts && len(opsum.NotifyTo) == 0) {
		return
	}

	// Собираем всех кандидатов на получение уведомления
	to := make([]string, 0, len(opsum.NotifyTo)+len(msg.Rcpts))
	to = append(to, opsum.NotifyTo...)

	if opsum.NotifyRcpts {
		// Фильтруем только локальных или специфичных получателей на основе вердикта
		rcptsFiltered := filterLocalRcpts(msg.Rcpts, res)
		to = append(to, rcptsFiltered...)
	}

	// Убираем дубликаты и пустые строки перед отправкой
	to = utils.UniqueSliceElementsNonEmpty(to)

	if len(to) > 0 && notifyfrom != "" {
		cgp.NotifyTo(seq, msg, to, hci, notifyfrom, desc)
	}
}
