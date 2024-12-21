package rspamc

import (
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"

	json "github.com/json-iterator/go"

	"git.vsu.ru/ai/rspamd-cgp/cgp"
	"git.vsu.ru/ai/rspamd-cgp/config"
	"git.vsu.ru/ai/rspamd-cgp/utils"
)

func filterLocalRcpts(rcpts []string, res map[string]interface{}) []string {

	filtered := make([]string, 0, len(rcpts))

	if v, ok := res["symbols"].(map[string]interface{})["RCPTS_DOMAINS_LOCAL"]; ok {
		if domains, ok := v.(map[string]interface{})["options"]; ok {
			for _, rcpt := range rcpts {
				for _, domain := range domains.([]interface{}) {
					if rcpt[strings.IndexByte(rcpt, '@')+1:len(rcpt)-1] == domain.(string) {
						filtered = append(filtered, rcpt)
						break
					}
				}
			}
		}
	}

	return filtered
}

func makeHeaders(res map[string]interface{}) (headers []string) {

	if _, ok := res["dkim-signature"]; ok {
		headers = append(headers, "DKIM-Signature: "+res["dkim-signature"].(string))
	}

	if milter, ok := res["milter"]; ok {
		if hdrs, ok := milter.(map[string]interface{})["add_headers"]; ok {
			if reflect.TypeOf(hdrs).String() == "map[string]interface {}" {
				for h, vh := range hdrs.(map[string]interface{}) {
					if reflect.TypeOf(vh).String() == "map[string]interface {}" {
						if v, ok := vh.(map[string]interface{})["value"].(string); ok && v != "" {
							headers = append(headers, h+": "+v)
						}
					}
				}
			}
		}
	}

	return
}

func makeHeadersOutbound(res map[string]interface{}) (headers []string) {

	if _, ok := res["dkim-signature"]; ok {
		headers = append(headers, "DKIM-Signature: "+res["dkim-signature"].(string))
	}

	return
}

func makeOpSum(conf *config.Config, res map[string]interface{}, action string) (*config.Operation, string, string, string) {

	var casea []string
	var desca []string
	opsum := new(config.Operation)

	if op, ok := conf.Actions[action]; ok {
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
	}

	for symbol, op := range conf.Symbols {
		if v, ok := res["symbols"].(map[string]interface{})[symbol]; ok {
			opsum.Discard = opsum.Discard || op.Discard
			opsum.MirrorTo = append(opsum.MirrorTo, op.MirrorTo...)
			opsum.NotifyRcpts = opsum.NotifyRcpts || op.NotifyRcpts
			opsum.NotifyTo = append(opsum.NotifyTo, op.NotifyTo...)
			casea = append(casea, symbol)

			if len(op.Description) > 0 {
				desca = append(desca, symbol+": "+op.Description)
			} else {
				if desc, ok := v.(map[string]interface{})["description"]; ok {
					desca = append(desca, symbol+": "+desc.(string))
				} else {
					desca = append(desca, symbol)
				}
			}
		}
	}

	if len(casea) > 0 {

		var sb strings.Builder
		sb.Grow(256)

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

func printMsgInfo(from string, rcpts []string, auth string, ip string, helo string, hostname string,
	qid int, seen bool) {

	fmt.Fprintln(os.Stderr, "from:    ", from)
	fmt.Fprintln(os.Stderr, "rcpts:   ", rcpts)
	fmt.Fprintln(os.Stderr, "ip:      ", ip)
	fmt.Fprintln(os.Stderr, "helo:    ", helo)
	fmt.Fprintln(os.Stderr, "hostname:", hostname)
	fmt.Fprintln(os.Stderr, "qid:     ", qid)
	if len(auth) > 0 {
		fmt.Fprintln(os.Stderr, "auth:    ", auth)
	} else {
		fmt.Fprintln(os.Stderr, "auth:     not authenticated")
	}
	fmt.Fprintln(os.Stderr, "seen:    ", seen)
	fmt.Fprintln(os.Stderr, "")
}

func printResponse(v any) {
	printed, _ := json.MarshalIndent(v, "", "  ")
	fmt.Fprintln(os.Stderr, string(printed))
}

func procAction(seq int, qid int, opsum *config.Operation, res map[string]interface{},
	headers []string, hci string, from string, rcpts []string, body []byte, notifyfrom string,
	desc string, outbound bool, t int) {

	if opsum != nil {

		if opsum.Discard {
			cgp.Putline("* %d [%d]: Action: discard; from %s, rcpts %s\n", seq, qid, from, strings.Join(rcpts, ","))
			cgp.AddHeaderWithMirrorTo(seq, qid, opsum.MirrorTo, opsum.Discard, headers, body, outbound)
		} else {
			to := utils.DiffSlice(opsum.MirrorTo, rcpts)
			cgp.AddHeaderWithMirrorTo(seq, qid, to, opsum.Discard, headers, body, outbound)
		}

		if len(opsum.NotifyTo) > 0 || opsum.NotifyRcpts {
			if opsum.NotifyRcpts {
				to := make([]string, 0, len(opsum.NotifyTo)+len(rcpts))
				to = append(to, opsum.NotifyTo...)
				rcpts_filtered := filterLocalRcpts(rcpts, res)
				to = append(to, rcpts_filtered...)
				to = utils.UniqueSliceElementsNonEmpty(to)
				cgp.NotifyTo(seq, qid, to, hci, from, rcpts, body, notifyfrom, desc)
			} else {
				cgp.NotifyTo(seq, qid, opsum.NotifyTo, hci, from, rcpts, body, notifyfrom, desc)
			}
		}

	} else {

		switch t {
		case 0:
			if len(headers) > 0 {
				cgp.AddHeader(seq, headers)
			} else {
				cgp.Ok(seq)
			}

		case 1:
			cgp.AddHeader(seq, headers)

		case 2:
			cgp.Discard(seq, qid, from, rcpts)
		}
	}
}

func procActionRS(seq int, qid int, opsum *config.Operation, res map[string]interface{},
	headers []string, hci string, subject string, from string, rcpts []string, body []byte,
	notifyfrom string, desc string, outbound bool) {

	err := cgp.RewriteSubject(seq, headers, subject, qid, from, rcpts, body)
	if err != nil {
		cgp.Failure(seq, qid, err)
	} else {

		if opsum != nil {
			cgp.AddHeaderWithMirrorTo(seq, qid, opsum.MirrorTo, opsum.Discard, headers, body, outbound)
			if len(opsum.NotifyTo) > 0 || opsum.NotifyRcpts {
				if opsum.NotifyRcpts {
					to := make([]string, 0, len(opsum.NotifyTo)+len(rcpts))
					to = append(to, opsum.NotifyTo...)
					rcpts_filtered := filterLocalRcpts(rcpts, res)
					to = append(to, rcpts_filtered...)
					to = utils.UniqueSliceElementsNonEmpty(to)
					cgp.NotifyTo(seq, qid, to, hci, from, rcpts, body, notifyfrom, desc)
				} else {
					cgp.NotifyTo(seq, qid, opsum.NotifyTo, hci, from, rcpts, body, notifyfrom, desc)
				}
			}

		} else {
			cgp.Discard(seq, qid, from, rcpts)
		}
	}
}
