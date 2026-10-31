#!/usr/bin/env python3
"""PhishGuard Lab: offline heuristic checks for suspicious URLs and email text."""
from __future__ import annotations

import argparse
import ipaddress
import json
import re
from urllib.parse import unquote, urlparse

URL_RE = re.compile(r"https?://[^\s<>\"']+", re.I)
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly",
    "ow.ly", "rb.gy", "shorturl.at",
}
SUSPICIOUS_WORDS = {
    "verify", "login", "password", "urgent", "invoice", "payment",
    "suspended", "wallet", "security", "confirm", "bonus", "prize",
}
BRAND_BAIT = {"paypal", "microsoft", "google", "apple", "bank", "kaspi", "amazon"}
SEVERITY_POINTS = {"high": 30, "medium": 15, "low": 5}


def _finding(rule: str, severity: str) -> dict:
    return {"rule": rule, "severity": severity}


def inspect_url(raw: str) -> dict:
    """Inspect a URL without DNS lookups, HTTP requests, or other network access."""
    if not isinstance(raw, str):
        raw = ""
    raw = raw.strip().rstrip(".,);]}")
    candidate = raw if "://" in raw else "https://" + raw

    try:
        parsed = urlparse(candidate)
        host = parsed.hostname or ""
        # Accessing .port validates malformed and out-of-range ports.
        port = parsed.port
    except ValueError:
        return {
            "url": raw,
            "host": "",
            "risk_score": 30,
            "findings": [_finding("invalid_url", "high")],
        }

    if parsed.scheme.lower() not in {"http", "https"} or not host:
        return {
            "url": raw,
            "host": host.lower(),
            "risk_score": 30,
            "findings": [_finding("invalid_url", "high")],
        }

    host = host.rstrip(".").lower()
    findings = []

    if parsed.username is not None or parsed.password is not None:
        findings.append(_finding("embedded_credentials", "high"))
    if parsed.scheme.lower() != "https":
        findings.append(_finding("not_https", "low"))

    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False

    if is_ip:
        findings.append(_finding("ip_address_host", "medium"))

    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError:
        ascii_host = host
        findings.append(_finding("invalid_idn_hostname", "high"))

    labels = ascii_host.split(".")
    if any(label.startswith("xn--") for label in labels):
        findings.append(_finding("punycode_domain", "medium"))
    if ascii_host in SHORTENERS:
        findings.append(_finding("url_shortener", "medium"))
    if len(labels) >= 5:
        findings.append(_finding("many_subdomains", "low"))

    # A brand appearing inside a hostname is suspicious unless it is the
    # brand's own .com domain or a subdomain of that exact domain.
    bait = [
        brand for brand in sorted(BRAND_BAIT)
        if brand in ascii_host
        and ascii_host not in {brand + ".com"}
        and not ascii_host.endswith("." + brand + ".com")
    ]
    if bait:
        findings.append(_finding("possible_brand_impersonation", "high"))

    decoded = unquote(parsed.path + "?" + parsed.query).lower()
    if any(word in decoded for word in SUSPICIOUS_WORDS):
        findings.append(_finding("suspicious_url_keywords", "low"))

    score = min(sum(SEVERITY_POINTS[item["severity"]] for item in findings), 100)
    return {
        "url": raw,
        "host": host,
        "risk_score": score,
        "findings": findings,
    }


def analyze_text(text: str) -> dict:
    """Extract and inspect URLs, then identify basic pressure-language indicators."""
    if not isinstance(text, str):
        text = ""

    urls = [inspect_url(url) for url in URL_RE.findall(text)]
    words = sorted(
        word for word in SUSPICIOUS_WORDS
        if re.search(r"\b" + re.escape(word) + r"\b", text, re.I)
    )
    urgency = bool(
        re.search(
            r"\b(within \d+ hours?|immediately|act now|account (?:will be|is) suspended)\b",
            text,
            re.I,
        )
    )
    return {
        "urls": urls,
        "message_indicators": {
            "urgency_language": urgency,
            "pressure_keywords": words,
        },
        "overall_note": (
            "Heuristic triage only. Verify the sender and destination "
            "through an independent trusted channel."
        ),
    }


def main():
    parser = argparse.ArgumentParser(
        description="Offline phishing triage. Does not open URLs or contact hosts."
    )
    parser.add_argument("input", help="Text file containing a message, or a URL")
    parser.add_argument("--output", help="Optional JSON report path")
    args = parser.parse_args()

    try:
        with open(args.input, encoding="utf-8") as file:
            content = file.read()
    except OSError as exc:
        parser.error(str(exc))

    report = analyze_text(content)
    if not report["urls"] and content.strip():
        candidate = content.strip()
        if re.match(r"^(https?://|[\w.-]+\.[a-z]{2,})(?::\d+)?(?:/|$)", candidate, re.I):
            report["urls"] = [inspect_url(candidate)]

    rendered = json.dumps(report, indent=2, ensure_ascii=False)
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as file:
                file.write(rendered + "\n")
        except OSError as exc:
            parser.error(f"cannot write report: {exc}")
    print(rendered)


if __name__ == "__main__":
    main()
