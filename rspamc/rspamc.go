package rspamc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"

	"git.vsu.ru/ai/rspamd-cgp/cgp"
	"git.vsu.ru/ai/rspamd-cgp/config"
)

type Duration float64

func (d Duration) Append(dst []byte) []byte {
	return strconv.AppendFloat(dst, float64(d), 'f', 6, 64)
}

type RspamdResponse struct {
	Action        string   `json:"action"`
	Score         float64  `json:"score"`
	RequiredScore float64  `json:"required_score"`
	TimeReal      Duration `json:"time_real"`
	Subject       string   `json:"subject,omitempty"`
	DKIMSignature string   `json:"dkim-signature,omitempty"`

	// Milter может отсутствовать (nil), если нет действий
	Milter *struct {
		AddHeaders map[string]struct {
			Value string `json:"value"`
		} `json:"add_headers"`
	} `json:"milter,omitempty"`

	// Symbols могут отсутствовать (nil)
	Symbols map[string]*Symbol `json:"symbols,omitempty"`
}

type Symbol struct {
	Score       float64  `json:"score"`
	Description string   `json:"description,omitempty"`
	Options     []string `json:"options,omitempty"`
}

var (
	client    *http.Client
	clientOne sync.Once
)

func Scan(seq int, filename string) {

	clientOne.Do(func() {
		client = &http.Client{
			Timeout: config.Timeout(),
			Transport: &http.Transport{
				DisableCompression: true,
			},
		}
	})

	msg, err := cgp.NewMessage(seq, filename)
	if err != nil {
		cgp.Failure(seq, 0, err)
		return
	}
	defer msg.Close()

	if msg.IsSeen() {
		cgp.OkSeen(seq, msg.QID)
		return
	}

	content := io.NewSectionReader(msg.File, msg.HdrPos, msg.Size-msg.HdrPos)
	req, err := http.NewRequest("POST", config.Host(), content)
	if err != nil {
		cgp.Failure(seq, msg.QID, err)
		return
	}

	req.Header.Add("MTA-Tag", config.AuthservId())
	req.Header.Add("User-Agent", "rspamd-cgp")
	req.Header.Add("From", msg.From)
	req.Header.Add("Queue-ID", strconv.Itoa(msg.QID))
	if len(msg.Auth) > 0 {
		req.Header.Add("User", msg.Auth)
	}
	if len(msg.IP) > 0 {
		req.Header.Add("IP", msg.IP)
	}
	if len(msg.Helo) > 0 {
		req.Header.Add("Helo", msg.Helo)
	}
	if len(msg.Hostname) > 0 {
		req.Header.Add("Hostname", msg.Hostname)
	}
	for _, rcpt := range msg.Rcpts {
		req.Header.Add("Rcpt", rcpt)
	}

	resp, err := client.Do(req)
	if err != nil {
		cgp.Failure(seq, msg.QID, err)
		return
	}
	defer resp.Body.Close()

	var res RspamdResponse
	var reader io.Reader = resp.Body
	var debugBuf *bytes.Buffer

	// Если Debug включен, копируем поток в буфер
	if config.Debug() {
		debugBuf = new(bytes.Buffer)
		reader = io.TeeReader(resp.Body, debugBuf)
	}

	if err := json.NewDecoder(reader).Decode(&res); err != nil {
		cgp.Failure(seq, msg.QID, err)
		return
	}

	if config.Debug() {
		msg.PrintMsgInfo()
		printResponse(debugBuf)
	}

	action := res.Action
	if action == "" {
		cgp.Failure(seq, msg.QID, fmt.Errorf("missing or invalid 'action' field"))
		return
	}

	opsum, caseinfo, casework, desc := makeOpSum(&res, action)

	var headers []string
	if config.Outbound() {
		headers = makeHeadersOutbound(&res)
	} else {
		headers = makeHeaders(&res)
	}

	cgp.Putline("* ", seq, " [", msg.QID, "]: Action: ", action,
		"; Score: ", res.Score, "/", res.RequiredScore, "; Time elapsed: ", res.TimeReal)

	var hci string
	if opsum != nil {
		cgp.Putline("* ", seq, " [", msg.QID, "]: Case: ", caseinfo, "; ", casework)
		hci = headerCase + caseinfo
		if !config.Outbound() {
			headers = append(headers, hci)
		}
	}

	procActionSwitch(seq, msg, opsum, &res, headers, hci, action, desc)
}
