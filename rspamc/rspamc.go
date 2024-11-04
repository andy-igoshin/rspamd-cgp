package rspamc

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"

	json "github.com/json-iterator/go"

	"git.vsu.ru/ai/rspamd-cgp/cgp"
	"git.vsu.ru/ai/rspamd-cgp/config"
)

const (
	headerJunkG string = "X-Junk-Score: [XX]"
	headerJunkA string = "X-Junk-Score: [XXXX]"
	headerJunkR string = "X-Junk-Score: [XXXXXXXXXX]"
)

func Scan(conf *config.Config, seq int, filename string) {

	tr := &http.Transport{
		DisableCompression: true,
	}

	client := &http.Client{
		Timeout:   conf.Timeout,
		Transport: tr,
	}

	from, rcpts, auth, ip, qid, body, seen, err := cgp.Message(filename)
	if err != nil {
		cgp.Failure(seq, qid, err)
		return
	}

	if seen {
		cgp.OkSeen(seq, qid)
		return
	}

	req, err := http.NewRequest("POST", conf.Host, bytes.NewReader(body))
	if err != nil {
		cgp.Failure(seq, qid, err)
		return
	}

	req.Header.Add("MTA-Tag", conf.AuthservId)
	req.Header.Add("User-Agent", "rspamd-cgp")
	req.Header.Add("From", from)
	req.Header.Add("Queue-ID", strconv.Itoa(qid))
	if len(auth) > 0 {
		req.Header.Add("User", auth)
	}
	if len(ip) > 0 {
		req.Header.Add("IP", ip)
	}
	for _, rcpt := range rcpts {
		req.Header.Add("Rcpt", rcpt)
	}

	resp, err := client.Do(req)
	if err != nil {
		cgp.Failure(seq, qid, err)
		return
	}
	defer resp.Body.Close()

	rbody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		cgp.Failure(seq, qid, err)
		return
	}

	var res map[string]interface{}
	if err := json.Unmarshal(rbody, &res); err != nil {
		cgp.Failure(seq, qid, err)
		return
	}

	if conf.Debug {
		printResponse(res)
	}

	action := res["action"].(string)
	headers := makeHeaders(res)
	opsum, casestr := makeOpSum(conf, res, action)

	cgp.Putline("* %d [%d]: Action: %s; Score: %.2f/%.2f; Time elapsed: %.3fs\n",
		seq, qid, action, res["score"], res["required_score"], res["time_real"])

	if opsum != nil {
		cgp.Putline("* %d [%d]: Case: %s\n", seq, qid, casestr)
	}

	switch action {
	case "no action":
		if len(headers) > 0 {
			cgp.AddHeader(seq, headers)
		} else {
			cgp.Ok(seq)
		}

	case "discard":
		cgp.Discard(seq, qid, from, rcpts)

	case "quarantine":
		//		cgp.MirrorTo(seq, qid, mirrorTo, append(headers, headerJunkR), body, mirrorDiscard)

	case "reject":
		cgp.AddHeader(seq, append(headers, headerJunkR))

	case "rewrite subject":
		if subject, ok := res["subject"]; ok {
			cgp.RewriteSubject(seq, append(headers, headerJunkA), subject.(string), qid, from, rcpts, body)
		} else {
			cgp.AddHeader(seq, append(headers, headerJunkA))
		}

	case "add header":
		cgp.AddHeader(seq, append(headers, headerJunkA))

	case "greylist":
		fallthrough
	case "soft reject":
		cgp.AddHeader(seq, append(headers, headerJunkG))

	default:
		cgp.Failure(seq, qid, fmt.Errorf("Unknown action: %v", action))
	}
}
