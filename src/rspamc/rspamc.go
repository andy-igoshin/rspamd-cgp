package rspamc

import (
	"bytes"
	"cgp"
	"config"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
)

var (
	headerJunkG string = "X-Junk-Score: [XX]"
	headerJunkA string = "X-Junk-Score: [XXXX]"
	headerJunkR string = "X-Junk-Score: [XXXXXXXXXX]"
)

var client *http.Client
var discard bool
var host string

func init() {

	config := config.New()

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
		cgp.Putline("* %d [%d]: %s\n", seq, qid, err)
		cgp.Putline("%d FAILURE\n", seq)
		return
	}

	req, err := http.NewRequest("POST", host, bytes.NewReader(body))
	if err != nil {
		cgp.Putline("* %d [%d]: %s\n", seq, qid, err)
		cgp.Putline("%d FAILURE\n", seq)
		return
	}

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
		cgp.Putline("* %d [%d]: %s\n", seq, qid, err)
		cgp.Putline("%d FAILURE\n", seq)
		return
	}
	defer resp.Body.Close()

	rbody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		cgp.Putline("* %d [%d]: %s\n", seq, qid, err)
		cgp.Putline("%d FAILURE\n", seq)
		return
	}

	var js map[string]interface{}
	if err := json.Unmarshal(rbody, &js); err != nil {
		cgp.Putline("* %d [%d]: %s\n", seq, qid, err)
		cgp.Putline("%d FAILURE\n", seq)
		return
	}

	action := js["action"]

	cgp.Putline("* %d [%d]: Action: %s; Score: %.2f/%.2f; Time elapsed: %.3fs\n",
		seq, qid, action, js["score"], js["required_score"], js["time_real"])

	var headers string

	if milter, ok := js["milter"]; ok {
		if hdrs, ok := milter.(map[string]interface{})["add_headers"]; ok {
			if ar, ok := hdrs.(map[string]interface{})["Authentication-Results"]; ok {
				if v, ok := ar.(map[string]interface{})["value"].(string); ok && v != "" {
					hdr := "Authentication-Results: " + strings.Replace(v, "; ", ";\n\t", -1)
					if headers != "" {
						headers = "\n" + hdr
					} else {
						headers = hdr
					}
				}
			}
		}
	}

	switch action {
	case "no action":
		if headers != "" {
			cgp.AddHeader(seq, cgp.ReplaceSpecChars(&headers))
		} else {
			cgp.Putline("%d OK\n", seq)
		}

	case "reject":
		if discard {
			cgp.Putline("%d DISCARD\n", seq)
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
		cgp.Putline("%d REJECT Try again later\n", seq)

	default:
		cgp.Putline("* %d [%d]: Unknown action: %v\n", seq, qid, action)
		cgp.Putline("%d FAILURE\n", seq)
	}

}
