package rspamc

import (
	"bytes"
	"cgp"
	"config"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
)

var (
	headerJunkG string = "X-Junk-Score: [XX]"
	headerJunkA string = "X-Junk-Score: [XXXX]"
	headerJunkR string = "X-Junk-Score: [XXXXXXXXXX]"
)

var authservId string
var client *http.Client
var discard bool
var host string

func init() {

	config := config.New()

	if config.AuthservId != "" {
		authservId = config.AuthservId
	} else {
		authservId = cgp.MainDomain
	}

	discard = config.Discard
	host = "http://" + config.Host + "/checkv2"

	tr := &http.Transport{
		DisableCompression: true,
	}

	client = &http.Client{
		Timeout:   config.Timeout,
		Transport: tr,
	}
}

func appendHeaders(hdrs, junk *string) *string {
	if *hdrs != "" {
		headers := *hdrs + "\n" + *junk
		return &headers
	} else {
		return junk
	}
}

func Scan(seq int, filename string) {

	from, rcpts, auth, ip, qid, body, err := cgp.Message(&filename)
	if err != nil {
		cgp.Failure(seq, qid, err)
		return
	}

	req, err := http.NewRequest("POST", host, bytes.NewReader(body))
	if err != nil {
		cgp.Failure(seq, qid, err)
		return
	}

	req.Header.Add("MTA-Tag", authservId)
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

	var js map[string]interface{}
	if err := json.Unmarshal(rbody, &js); err != nil {
		cgp.Failure(seq, qid, err)
		return
	}

	var headers string

	if _, ok := js["dkim-signature"]; ok {
		headers = "DKIM-Signature: " + js["dkim-signature"].(string)
	}

	if milter, ok := js["milter"]; ok {
		if hdrs, ok := milter.(map[string]interface{})["add_headers"]; ok {
			for h, vh := range hdrs.(map[string]interface{}) {
				if v, ok := vh.(map[string]interface{})["value"].(string); ok && v != "" {
					if headers != "" {
						headers += "\n" + h + ": " + v
					} else {
						headers = h + ": " + v
					}
				}
			}
		}
	}

	action := js["action"]

	cgp.Putline("* %d [%d]: Action: %s; Score: %.2f/%.2f; Time elapsed: %.3fs\n",
		seq, qid, action, js["score"], js["required_score"], js["time_real"])

	switch action {
	case "no action":
		if headers != "" {
			cgp.AddHeader(seq, cgp.ReplaceSpecChars(&headers))
		} else {
			cgp.Ok(seq)
		}

	case "reject":
		if discard {
			cgp.Discard(seq)
		} else {
			cgp.AddHeader(seq, cgp.ReplaceSpecChars(appendHeaders(&headers, &headerJunkR)))
		}

	case "rewrite subject":
		fallthrough
	case "add header":
		cgp.AddHeader(seq, cgp.ReplaceSpecChars(appendHeaders(&headers, &headerJunkA)))

	case "greylist":
		cgp.AddHeader(seq, cgp.ReplaceSpecChars(appendHeaders(&headers, &headerJunkG)))

	case "soft reject":
		cgp.Reject(seq)

	default:
		cgp.Failure(seq, qid, fmt.Errorf("Unknown action: %v", action))
	}

}
