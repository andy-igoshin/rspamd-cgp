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

func makeOpSum(conf *config.Config, res map[string]interface{}, action string) (*config.Operation, string, string, string) {

	var casea []string
	var desca []string
	opsum := new(config.Operation)

	if op, ok := conf.Actions[action]; ok {
		opsum.Discard = op.Discard
		opsum.MirrorTo = op.MirrorTo
		opsum.NotifySelf = op.NotifySelf
		opsum.NotifyTo = op.NotifyTo
		casea = append(casea, action)

		if len(op.Description) > 0 {
			desca = append(desca, action+": "+op.Description)
		} else {
			desca = append(desca, action)
		}
	}

	for symbol, op := range conf.Symbols {
		if _, ok := res["symbols"].(map[string]interface{})[symbol]; ok {
			opsum.Discard = opsum.Discard || op.Discard
			opsum.MirrorTo = append(opsum.MirrorTo, op.MirrorTo...)
			opsum.NotifySelf = opsum.NotifySelf || op.NotifySelf
			opsum.NotifyTo = append(opsum.NotifyTo, op.NotifyTo...)
			casea = append(casea, symbol)

			if len(op.Description) > 0 {
				desca = append(desca, symbol+": "+op.Description)
			} else {
				desca = append(desca, symbol)
			}
		}
	}

	if len(casea) > 0 {

		var sb strings.Builder
		sb.Grow(256)

		sb.WriteString("Discard: ")
		sb.WriteString(strconv.FormatBool(opsum.Discard))

		sb.WriteString("; NotifySelf: ")
		sb.WriteString(strconv.FormatBool(opsum.NotifySelf))

		if len(opsum.MirrorTo) > 0 {
			opsum.MirrorTo = utils.UniqueSliceElementsNonEmpty(opsum.MirrorTo)
			sb.WriteString("; MirrorTo: ")
			sb.WriteString(strings.Join(opsum.MirrorTo, ","))
		}

		if len(opsum.NotifyTo) > 0 {
			opsum.NotifyTo = utils.UniqueSliceElementsNonEmpty(opsum.NotifyTo)
			sb.WriteString("; NotifyTo: ")
			sb.WriteString(strings.Join(opsum.NotifyTo, ","))
		}

		return opsum, strings.Join(casea, ","), sb.String(), strings.Join(desca, "\n")
	}

	return nil, "", "", ""
}

func printResponse(v any) {
	printed, _ := json.MarshalIndent(v, "", "  ")
	fmt.Fprintln(os.Stderr, string(printed))
}

func procAction(seq int, qid int, opsum *config.Operation, headers []string, hci string,
	from string, rcpts []string, body []byte, notifyfrom string, desc string, t int) {

	if opsum != nil {

		if opsum.Discard {
			cgp.AddHeaderWithMirrorTo(seq, qid, opsum.MirrorTo, opsum.Discard, headers, body)
		} else {
			to := utils.DiffSlice(opsum.MirrorTo, rcpts)
			cgp.AddHeaderWithMirrorTo(seq, qid, to, opsum.Discard, headers, body)
		}

		if len(opsum.NotifyTo) > 0 || opsum.NotifySelf {
			if opsum.NotifySelf {
				to := make([]string, 0, len(opsum.NotifyTo)+len(rcpts))
				to = append(to, opsum.NotifyTo...)
				to = append(to, rcpts...)
				to = utils.UniqueSliceElementsNonEmpty(to)
				cgp.NotifyTo(seq, qid, to, opsum.NotifySelf, hci, from, rcpts, body, notifyfrom, desc)
			} else {
				cgp.NotifyTo(seq, qid, opsum.NotifyTo, opsum.NotifySelf, hci, from, rcpts, body, notifyfrom, desc)
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
