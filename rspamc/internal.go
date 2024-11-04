package rspamc

import (
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"

	json "github.com/json-iterator/go"

	"git.vsu.ru/ai/rspamd-cgp/config"
	"git.vsu.ru/ai/rspamd-cgp/utils"
)

func makeHeaders(res map[string]interface{}) (headers []string) {

	if _, ok := res["dkim-signature"]; ok {
		headers = append(headers, strings.Join([]string{"DKIM-Signature: ", res["dkim-signature"].(string)}, ""))
	}

	if milter, ok := res["milter"]; ok {
		if hdrs, ok := milter.(map[string]interface{})["add_headers"]; ok {
			if reflect.TypeOf(hdrs).String() == "map[string]interface {}" {
				for h, vh := range hdrs.(map[string]interface{}) {
					if reflect.TypeOf(vh).String() == "map[string]interface {}" {
						if v, ok := vh.(map[string]interface{})["value"].(string); ok && v != "" {
							headers = append(headers, strings.Join([]string{h, v}, ": "))
						}
					}
				}
			}
		}
	}

	return
}

func makeOpSum(conf *config.Config, res map[string]interface{}, action string) (*config.Operation, string) {

	var casea []string
	opsum := new(config.Operation)

	if op, ok := conf.Actions[action]; ok {
		opsum.Discard = op.Discard
		opsum.MirrorTo = op.MirrorTo
		opsum.NotifySelf = op.NotifySelf
		opsum.NotifyTo = op.NotifyTo
		casea = append(casea, action)
	}

	for symbol, op := range conf.Symbols {
		if _, ok := res["symbols"].(map[string]interface{})[symbol]; ok {
			opsum.Discard = opsum.Discard || op.Discard
			opsum.MirrorTo = append(opsum.MirrorTo, op.MirrorTo...)
			opsum.NotifySelf = opsum.NotifySelf || op.NotifySelf
			opsum.NotifyTo = append(opsum.NotifyTo, op.NotifyTo...)
			casea = append(casea, symbol)
		}
	}

	if len(casea) > 0 {

		var sb strings.Builder
		sb.Grow(256)

		sb.WriteString(strings.Join(casea, ","))

		sb.WriteString("; Discard: ")
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

		return opsum, sb.String()
	}

	return nil, ""
}

func printResponse(v any) {
	printed, _ := json.MarshalIndent(v, "", "  ")
	fmt.Fprintln(os.Stderr, string(printed))
}
