
    Rspamd plugin for CommuniGate Pro 5.x, 6.x

    Installation and usage instructions can be found at
    http://www.communigate.com/CGPMcAfee/#Integrate


    Copyright (C) 2017-2021 Andrey Igoshin <ai@vsu.ru>
    Version 1.3.0

    https://git.vsu.ru/ai/rspamd-cgp


    Usage of rspamd-cgp:
      -authserv-id string
            Authentication Identifier (default CommuniGate Pro Main Domain)
      -host string
            Rspamd host to connect (default "localhost:11333")
      -reject-action string
            Reject action: "add_header" or "discard" (default "add_header")
      -timeout duration
            Rspamd request timeout (default 15s)
