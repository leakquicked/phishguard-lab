# PhishGuard Lab

Offline phishing-triage helper for security education. It inspects message text and URLs using transparent heuristics; it **never opens URLs, resolves domains, or contacts remote hosts**.

## Features
- Flags URL shorteners, non-HTTPS URLs, punycode, IP-address hosts, embedded credentials, suspicious URL keywords and possible brand impersonation.
- Highlights urgency and pressure language in message text.
- Produces a JSON report.

## Run
Python 3.10+; standard library only.

```bash
python phishguard.py sample_message.txt
python phishguard.py sample_message.txt --output triage.json
python -m unittest discover -s tests -v
```

## Limitations and safe use
This is a learning aid, not an email gateway or definitive phishing detector. Heuristics can produce false positives and miss sophisticated attacks. Never enter credentials into links from untrusted messages. Verify requests through a known, independent channel. The tool does not fetch URLs or upload message contents.

Only analyze messages you are authorized to handle. Review reports before sharing; message text can contain personal information.
