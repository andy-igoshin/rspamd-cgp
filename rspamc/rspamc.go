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
	headerCase  string = "X-Rspamd-Case: "
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

	from, rcpts, auth, ip, helo, qid, body, seen, err := cgp.Message(filename)
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
	if len(helo) > 0 {
		req.Header.Add("Helo", helo)
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
		printMsgInfo(from, rcpts, auth, ip, helo, qid, seen)
		printResponse(res)
	}

	action := res["action"].(string)
	headers := makeHeaders(res)
	opsum, caseinfo, casework, desc := makeOpSum(conf, res, action)

	cgp.Putline("* %d [%d]: Action: %s; Score: %.2f/%.2f; Time elapsed: %.3fs\n",
		seq, qid, action, res["score"], res["required_score"], res["time_real"])

	var hci string

	if opsum != nil {
		cgp.Putline("* %d [%d]: Case: %s; %s\n", seq, qid, caseinfo, casework)
		hci = headerCase + caseinfo
		headers = append(headers, hci)
	}

	switch action {
	case "no action":
		procAction(seq, qid, opsum, res, headers, hci, from, rcpts, body, conf.NotifyFrom, desc, 0)

	case "discard":
		procAction(seq, qid, opsum, res, append(headers, headerJunkR), hci, from, rcpts, body, conf.NotifyFrom, desc, 2)

	case "quarantine":
		fallthrough
	case "reject":
		procAction(seq, qid, opsum, res, append(headers, headerJunkR), hci, from, rcpts, body, conf.NotifyFrom, desc, 1)

	case "rewrite subject":
		if subject, ok := res["subject"]; ok {
			procActionRS(seq, qid, opsum, res, append(headers, headerJunkA), hci, subject.(string), from, rcpts, body, conf.NotifyFrom, desc)
		} else {
			procAction(seq, qid, opsum, res, headers, hci, from, rcpts, body, conf.NotifyFrom, desc, 1)
		}

	case "add header":
		procAction(seq, qid, opsum, res, append(headers, headerJunkA), hci, from, rcpts, body, conf.NotifyFrom, desc, 1)

	case "greylist":
		fallthrough
	case "soft reject":
		procAction(seq, qid, opsum, res, append(headers, headerJunkG), hci, from, rcpts, body, conf.NotifyFrom, desc, 1)

	default:
		cgp.Failure(seq, qid, fmt.Errorf("Unknown action: %v", action))
	}
}
