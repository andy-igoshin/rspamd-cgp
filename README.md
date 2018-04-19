
    Rspamd plugin for CommuniGate Pro 6.x,
    External Filter protocol version 4

    Installation and usage instructions can be found at
    http://www.communigate.com/CGPMcAfee/#Integrate


    Copyright (C) 2017-2018 Andrey Igoshin <ai@vsu.ru>
    Version 1.2.2

    https://git.vsu.ru/ai/rspamd-cgp


    Usage of rspamd-cgp:
      -host string
            Rspamd host to connect (default "localhost:11333")
      -reject-action string
            Reject action: "add_header" or "discard" (default "add_header")
      -timeout duration
            Rspamd request timeout (default 15s)
