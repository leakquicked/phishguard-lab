#!/usr/bin/env python3
"""PhishGuard Lab: offline heuristic checks for suspicious URLs and email text."""
import argparse, json, re
from urllib.parse import urlparse, unquote

URL_RE = re.compile(r"https?://[^\s<>\"']+", re.I)
SHORTENERS = {"bit.ly","tinyurl.com","t.co","is.gd","cutt.ly","ow.ly","rb.gy","shorturl.at"}
SUSPICIOUS_WORDS = {"verify","login","password","urgent","invoice","payment","suspended","wallet","security","confirm","bonus","prize"}
BRAND_BAIT = {"paypal","microsoft","google","apple","bank","kaspi","amazon"}

def inspect_url(raw):
    raw = raw.strip().rstrip(".,);]}")
    parsed = urlparse(raw if "://" in raw else "https://" + raw)
    host = (parsed.hostname or "").lower()
    findings=[]
    if not host: findings.append(("invalid_url","high"))
    if parsed.scheme != "https": findings.append(("not_https","low"))
    if parsed.username or parsed.password: findings.append(("embedded_credentials","high"))
    if host in SHORTENERS: findings.append(("url_shortener","medium"))
    if host.startswith("xn--") or ".xn--" in host: findings.append(("punycode_domain","medium"))
    if len(host.split(".")) >= 5: findings.append(("many_subdomains","low"))
    if re.search(r"\d{1,3}(?:\.\d{1,3}){3}", host): findings.append(("ip_address_host","medium"))
    decoded=unquote(parsed.path + "?" + parsed.query).lower()
    hits=sorted(w for w in SUSPICIOUS_WORDS if w in decoded)
    if hits: findings.append(("suspicious_url_keywords","low"))
    bait=sorted(b for b in BRAND_BAIT if b in host and not (host == b+".com" or host.endswith("."+b+".com")))
    if bait: findings.append(("possible_brand_impersonation","high"))
    score=sum({"high":30,"medium":15,"low":5}[severity] for _,severity in findings)
    return {"url":raw,"host":host,"risk_score":min(score,100),"findings":[{"rule":r,"severity":s} for r,s in findings]}

def analyze_text(text):
    urls=[inspect_url(u) for u in URL_RE.findall(text)]
    words=[w for w in SUSPICIOUS_WORDS if re.search(r"\b"+re.escape(w)+r"\b",text,re.I)]
    urgency=bool(re.search(r"\b(within \d+ hours?|immediately|act now|account (?:will be|is) suspended)\b",text,re.I))
    return {"urls":urls,"message_indicators":{"urgency_language":urgency,"pressure_keywords":sorted(words)},
            "overall_note":"Heuristic triage only. Verify the sender and destination through an independent trusted channel."}

def main():
    p=argparse.ArgumentParser(description="Offline phishing triage. Does not open URLs or contact hosts.")
    p.add_argument("input",help="Text file containing a message, or a URL")
    p.add_argument("--output",help="Optional JSON report path")
    a=p.parse_args()
    try: content=open(a.input,encoding="utf-8").read()
    except OSError as e: p.error(str(e))
    report=analyze_text(content)
    if not report["urls"] and re.match(r"^(https?://|[\w.-]+\.[a-z]{2,})",content.strip(),re.I):
        report["urls"]=[inspect_url(content.strip())]
    rendered=json.dumps(report,indent=2,ensure_ascii=False)
    if a.output:
        with open(a.output,"w",encoding="utf-8") as f: f.write(rendered+"\n")
    print(rendered)
if __name__=="__main__": main()
