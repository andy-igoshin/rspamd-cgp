package main

import (
	"bufio"
	"cgp"
	"fmt"
	"io"
	"os"
	"rspamc"
)

func main() {

	var arg, cmd string
	var seq int
	var line []byte
	var err error
	var n int

	in := bufio.NewReader(os.Stdin)

finalize:
	for {
		line, err = in.ReadSlice('\n')
		if err != nil {
			cgp.Putline("* error: %s\n", err)
			break finalize
		}

		n, err = fmt.Sscan(string(line), &seq, &cmd, &arg)
		if err != nil && err != io.EOF {
			cgp.Putline("* error: %s\n", err)
			continue
		}

		switch {
		case cmd == "FILE" && n == 3:
			go rspamc.Scan(seq, arg)

		case cmd == "INTF" && n == 3:
			cgp.Putline("%d INTF %d\n", seq, cgp.Protocol(arg))

		case cmd == "QUIT" && n == 2:
			cgp.Ok(seq)
			break finalize

		default:
			cgp.Putline("* bad command: %s", line)
		}
	}

}
