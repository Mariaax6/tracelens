# Security policy

TraceLens only reads one capture file and writes three report files; it does not capture traffic, open sockets or run commands. Capture files are treated as **untrusted input**: every length field is validated before use, state is bounded and values are escaped in HTML, CSV and JSON.

If you find a vulnerability, for example a crafted PCAP that crashes the reader or an escaping bypass in a report, please use GitHub's **Report a vulnerability** option on the Security tab of this repository instead of opening a public issue.

Never attach real captures to issues: they can contain credentials, personal data and internal addresses. Reproduce problems with a synthetic capture built with `Fixtures` instead.
