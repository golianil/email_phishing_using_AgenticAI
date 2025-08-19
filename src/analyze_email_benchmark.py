#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
analyze_email.py
-------------------------------------------------
Offline email phishing & malware triage for downloaded .eml files.

Features:
- Parse headers: Subject, From, To, Date, Return-Path, Message-ID, MIME-Version,
  X-Spam-Status, Received, Authentication-Results (SPF/DKIM/DMARC).
- Compute SHA256 of the text body and each attachment.
- Extract URLs and flag risky patterns (shorteners, IP links, punycode, etc.).
- Simple heuristic scoring -> verdict (Benign / Suspicious / Malicious).
- Export results to CSV (one row per email), optionally extract attachments.

Stdlib-only. Tested with Python 3.9+.
"""

import argparse
import base64
import csv
import email
import hashlib
import html
import os
import quopri
import re
import sys
import textwrap
import time
import math
from collections import defaultdict, Counter
from email import policy
from email.parser import BytesParser
from email.utils import parsedate_to_datetime, getaddresses
from urllib.parse import urlparse
from datetime import datetime

# ---------------------------- Constants -------------------------------- #

SUSPICIOUS_EXTENSIONS = {
    # Executables / scripts
    "exe","scr","pif","com","jar","msi","bat","cmd","vbs","js","jse","wsf","ps1","hta","lnk",
    # Disc images / containers
    "iso","img","vhd","vhdx",
    # Archives
    "zip","rar","7z","cab",
    # Office macros / templates
    "docm","xlsm","pptm","dotm","xltm","ppam","ppsm","sldm",
    # Legacy Office (often abused)
    "doc","xls","ppt",
    # HTML delivery
    "html","htm","shtml","xhtml"
}

URL_SHORTENERS = {
    "bit.ly","tinyurl.com","t.co","goo.gl","buff.ly","ow.ly","is.gd","rebrand.ly","cutt.ly",
    "t.ly","rb.gy","s.id","shorturl.at","v.gd","shorte.st","bc.vc","lnkd.in"
}

SUSPICIOUS_KEYWORDS = {
    "urgent","verify","account","suspended","invoice","payment","overdue","reset","password",
    "confirm","update","unusual activity","limited time","gift card","crypto","transfer","wire"
}

DOUBLE_EXT_RE = re.compile(r"\.([A-Za-z0-9]{1,5})\.(exe|scr|js|vbs|bat|cmd|ps1|jar|msi|lnk|hta)$", re.I)
PUNYCODE_RE = re.compile(r"\bxn--", re.I)
URL_RE = re.compile(r"""(?i)\b((?:https?://|www\.)[^\s<>"'()]+)""")
IP_URL_RE = re.compile(r"""https?://(?:\d{1,3}\.){3}\d{1,3}\b""", re.I)
AT_SYMBOL_URL_RE = re.compile(r"https?://[^/\s]*@[^/\s]+", re.I)

# ---------------------------- Helpers ---------------------------------- #

def sha256_bytes(b: bytes) -> str:
    h = hashlib.sha256()
    h.update(b or b"")
    return h.hexdigest()

def clean_ws(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "").strip())

def get_domain_from_email(addr: str) -> str:
    if not addr or "@" not in addr:
        return ""
    return addr.split("@", 1)[1].lower().strip(" >.")

def get_domains_from_urls(urls):
    doms = []
    for u in urls:
        try:
            if u.lower().startswith("www."):
                u = "http://" + u  # allow urlparse to parse bare www
            netloc = urlparse(u).netloc.lower()
            if netloc:
                doms.append(netloc)
        except Exception:
            pass
    return sorted(set(doms))

def decode_header_value(msg, name):
    """Return a best-effort unicode string for a header."""
    raw = msg.get(name)
    if raw is None:
        return ""
    try:
        from email.header import decode_header, make_header
        return str(make_header(decode_header(raw)))
    except Exception:
        return str(raw)

def get_all_headers_raw(msg) -> str:
    try:
        lines = []
        for k, v in msg.raw_items():
            lines.append(f"{k}: {v}")
        return "\n".join(lines)
    except Exception:
        # Fallback if policy/raw_items not available
        return msg.as_string().split("\n\n", 1)[0]

def extract_received_chain(msg):
    recvd = msg.get_all("Received", [])
    # Normalize whitespace for readability
    return [clean_ws(x) for x in recvd]

def extract_auth_results(msg):
    """Parse Authentication-Results and Received-SPF for SPF/DKIM/DMARC."""
    spf = ""
    dkim = ""
    dmarc = ""

    # Authentication-Results may appear multiple times; parse all
    for ar in msg.get_all("Authentication-Results", []) or []:
        ar_l = ar.lower()
        if "spf=" in ar_l and not spf:
            m = re.search(r"spf=(pass|fail|softfail|neutral|none|temperror|permerror)", ar_l)
            if m: spf = m.group(1)
        if "dkim=" in ar_l and not dkim:
            m = re.search(r"dkim=(pass|fail|none|policy|neutral|temperror|permerror)", ar_l)
            if m: dkim = m.group(1)
        if "dmarc=" in ar_l and not dmarc:
            m = re.search(r"dmarc=(pass|fail|none|quarantine|reject)", ar_l)
            if m: dmarc = m.group(1)

    # Received-SPF: often present
    if not spf:
        for rs in msg.get_all("Received-SPF", []) or []:
            m = re.search(r"^(pass|fail|softfail|neutral|none)", rs.lower())
            if m:
                spf = m.group(1)
                break

    return spf or "unknown", dkim or "unknown", dmarc or "unknown"

def decode_part(part):
    """Return (bytes, content_type, is_text, is_html) for a single part."""
    ctype = part.get_content_type() or "application/octet-stream"
    is_text = ctype.startswith("text/")
    is_html = ctype == "text/html"
    try:
        payload = part.get_payload(decode=True)
        if payload is None and is_text:
            # Sometimes not encoded; get_payload() returns str
            txt = part.get_payload()
            if isinstance(txt, str):
                payload = txt.encode(part.get_content_charset() or "utf-8", errors="ignore")
    except Exception:
        payload = b""
    return payload or b"", ctype, is_text, is_html

def extract_body_text(msg):
    """
    Prefer text/plain; fall back to text/html (stripped).
    Return (text, body_bytes, has_html_form, has_html_script, base64_ratio)
    """
    text_candidates = []
    html_candidates = []
    base64_total = 0
    base64_encoded = 0

    if msg.is_multipart():
        for part in msg.walk():
            if part.is_multipart():
                continue
            payload, ctype, is_text, is_html = decode_part(part)
            if not payload:
                continue

            # Track base64 density as basic obfuscation signal
            base64_total += len(payload)
            # crude heuristic: if it decodes cleanly from base64, count it
            try:
                d = base64.b64decode(payload, validate=True)
                if d and len(d) > 32:
                    base64_encoded += len(payload)
            except Exception:
                pass

            if ctype == "text/plain":
                try:
                    text_candidates.append(payload.decode(part.get_content_charset() or "utf-8", errors="ignore"))
                except Exception:
                    pass
            elif ctype == "text/html":
                try:
                    html_candidates.append(payload.decode(part.get_content_charset() or "utf-8", errors="ignore"))
                except Exception:
                    pass
    else:
        payload, ctype, is_text, is_html = decode_part(msg)
        if ctype == "text/plain":
            text_candidates.append(payload.decode("utf-8", errors="ignore"))
        elif ctype == "text/html":
            html_candidates.append(payload.decode("utf-8", errors="ignore"))

    text_body = ""
    has_form = False
    has_script = False

    if text_candidates:
        text_body = "\n".join(text_candidates)
    elif html_candidates:
        # Very basic HTML -> text
        html_combined = "\n".join(html_candidates)
        has_form = bool(re.search(r"<form\b", html_combined, re.I))
        has_script = bool(re.search(r"<script\b", html_combined, re.I))
        # strip tags
        text_body = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", html_combined)
        text_body = re.sub(r"(?is)<br\s*/?>", "\n", text_body)
        text_body = re.sub(r"(?is)<[^>]+>", " ", text_body)
        text_body = html.unescape(text_body)

    text_body = textwrap.dedent(text_body or "").strip()
    body_bytes = text_body.encode("utf-8", errors="ignore")
    base64_ratio = (base64_encoded / base64_total) if base64_total else 0.0

    return text_body, body_bytes, has_form, has_script, base64_ratio

def extract_urls(text):
    urls = URL_RE.findall(text or "")
    # Normalize and dedupe
    cleaned = []
    for u in urls:
        if u.lower().startswith("www."):
            u = "http://" + u
        cleaned.append(u.strip().rstrip(").,;\"'"))
    return sorted(set(cleaned))

def attachment_info(msg, outdir=None):
    """
    Return list of dicts: name, mime, size, sha256.
    Optionally write attachments to outdir (no overwrite).
    """
    infos = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        if part.get_content_disposition() not in ("attachment", "inline"):
            # Some malware arrives as inline attachments; include both.
            continue

        fname = part.get_filename()
        if not fname:
            # Try content-type name=
            fname = part.get_param("name")
        fname = fname or "unnamed.bin"

        data, ctype, _, _ = decode_part(part)
        sha = sha256_bytes(data)
        size = len(data)

        if outdir:
            try:
                os.makedirs(outdir, exist_ok=True)
                safe_name = fname.replace("/", "_").replace("\\", "_")
                out_path = os.path.join(outdir, safe_name)
                if not os.path.exists(out_path):
                    with open(out_path, "wb") as f:
                        f.write(data)
            except Exception:
                pass

        infos.append({
            "name": fname,
            "mime": ctype,
            "size": size,
            "sha256": sha
        })
    return infos

def header_bool(header_value):
    if not header_value:
        return False
    return header_value.strip().lower().startswith("yes")

def parse_addresses(header_value):
    addrs = []
    for name, addr in getaddresses([header_value or ""]):
        addrs.append((name, addr))
    return addrs

def score_email(context):
    """
    Compute a heuristic score (0-100+) and reasons list.
    Higher = riskier.
    """
    score = 0
    reasons = []

    # Auth results
    spf = context["spf"]
    dkim = context["dkim"]
    dmarc = context["dmarc"]

    if spf in ("fail", "softfail"): score += 20; reasons.append(f"SPF={spf}")
    elif spf == "none": score += 10; reasons.append("SPF=none")
    elif spf == "unknown": score += 5; reasons.append("SPF=unknown")

    if dkim in ("fail",): score += 20; reasons.append(f"DKIM={dkim}")
    elif dkim in ("none","unknown"): score += 10; reasons.append(f"DKIM={dkim}")

    if dmarc in ("fail","quarantine","reject"): score += 25; reasons.append(f"DMARC={dmarc}")
    elif dmarc in ("none","unknown"): score += 10; reasons.append(f"DMARC={dmarc}")

    # X-Spam-Status
    xspam = context["x_spam_status"]
    if xspam.startswith("yes"):
        score += 25; reasons.append(f"X-Spam-Status={xspam}")

    # Domain alignment checks
    from_dom = context["from_domain"]
    return_dom = context["return_path_domain"]
    reply_dom = context["reply_to_domain"]
    dkim_dom = context["dkim_domain"]

    if from_dom and return_dom and from_dom != return_dom:
        score += 10; reasons.append(f"From domain ({from_dom}) ≠ Return-Path ({return_dom})")
    if from_dom and reply_dom and reply_dom != "" and from_dom != reply_dom:
        score += 10; reasons.append(f"From domain ({from_dom}) ≠ Reply-To ({reply_dom})")
    if from_dom and dkim_dom and from_dom != dkim_dom:
        score += 10; reasons.append(f"From domain ({from_dom}) ≠ DKIM d= ({dkim_dom})")

    # URLs
    urls = context["urls"]
    url_domains = context["url_domains"]
    if urls:
        # IP literal URLs
        if any(IP_URL_RE.match(u) for u in urls):
            score += 15; reasons.append("URL uses bare IP address")
        # '@' in URL userinfo
        if any(AT_SYMBOL_URL_RE.search(u) for u in urls):
            score += 15; reasons.append("URL contains '@' userinfo")
        # Shorteners
        if any(dom in URL_SHORTENERS for dom in url_domains):
            score += 10; reasons.append("URL shortener detected")
        # Punycode (homograph) domains
        if any(PUNYCODE_RE.search(dom) for dom in url_domains):
            score += 15; reasons.append("Punycode domain in URL")

        # Mismatch between From domain and link domains (excluding subdomains)
        if from_dom:
            mismatched = [d for d in url_domains if from_dom not in d and not d.endswith("." + from_dom)]
            if mismatched and len(set(mismatched)) >= 1:
                score += 10; reasons.append("Link domains differ from sender domain")

    # Attachments
    for att in context["attachments"]:
        name = att["name"]
        ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
        if ext in SUSPICIOUS_EXTENSIONS:
            score += 20; reasons.append(f"Suspicious attachment: .{ext}")
        if DOUBLE_EXT_RE.search(name):
            score += 25; reasons.append("Double-extension attachment")
        if name.lower().count(" ") > 5 and ext in {"exe","scr","js","vbs","bat","cmd","ps1"}:
            score += 10; reasons.append("Executable with padding spaces in name")

    # HTML risks
    if context["has_html_form"]:
        score += 10; reasons.append("HTML form in body")
    if context["has_html_script"]:
        score += 10; reasons.append("Script tag in body")

    # Obfuscation (high base64 density)
    if context["base64_ratio"] > 0.5:
        score += 10; reasons.append("High base64 density in parts")

    # Keywords
    body_low = (context["body_text"] or "").lower()
    if any(k in body_low for k in SUSPICIOUS_KEYWORDS):
        score += 8; reasons.append("Suspicious keywords in body")

    # Normalize and cap
    score = min(score, 100)
    verdict = "Benign"
    if score >= 70:
        verdict = "Malicious"
    elif score >= 40:
        verdict = "Suspicious"

    return score, verdict, reasons

def parse_dkim_domain(msg):
    # Try DKIM-Signature: d=example.com
    for dk in msg.get_all("DKIM-Signature", []) or []:
        m = re.search(r"\bd=([^;,\s]+)", dk)
        if m:
            return m.group(1).lower()
    # Fallback: Authentication-Results; dkim=pass header.d=example.com
    for ar in msg.get_all("Authentication-Results", []) or []:
        m = re.search(r"header\.d=([^;,\s]+)", ar)
        if m:
            return m.group(1).lower()
    return ""

def analyze_eml(path, extract_dir=None):
    with open(path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    subject = decode_header_value(msg, "Subject")
    from_h = decode_header_value(msg, "From")
    to_h = decode_header_value(msg, "To")
    date_h = decode_header_value(msg, "Date")
    msg_id = decode_header_value(msg, "Message-ID")
    mime_ver = decode_header_value(msg, "MIME-Version")
    return_path = decode_header_value(msg, "Return-Path")
    reply_to = decode_header_value(msg, "Reply-To")
    x_spam_status = decode_header_value(msg, "X-Spam-Status").lower()

    received_chain = extract_received_chain(msg)
    raw_headers = get_all_headers_raw(msg)

    spf, dkim, dmarc = extract_auth_results(msg)
    dkim_domain = parse_dkim_domain(msg)

    # Addresses & domains
    from_addrs = parse_addresses(from_h)
    to_addrs = parse_addresses(to_h)
    reply_addrs = parse_addresses(reply_to)

    from_display = from_addrs[0][0] if from_addrs else ""
    from_addr = from_addrs[0][1] if from_addrs else ""
    from_domain = get_domain_from_email(from_addr)

    return_path_addr = return_path.strip("<> ") if return_path else ""
    return_path_domain = get_domain_from_email(return_path_addr)

    reply_to_addr = reply_addrs[0][1] if reply_addrs else ""
    reply_to_domain = get_domain_from_email(reply_to_addr)

    # Body & URLs
    body_text, body_bytes, has_form, has_script, base64_ratio = extract_body_text(msg)
    urls = extract_urls(body_text)
    url_domains = get_domains_from_urls(urls)
    body_sha256 = sha256_bytes(body_bytes)

    # Attachments
    atts = attachment_info(msg, outdir=extract_dir)

    # Compose context for scoring
    ctx = {
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
        "x_spam_status": x_spam_status or "unknown",
        "from_domain": from_domain,
        "return_path_domain": return_path_domain,
        "reply_to_domain": reply_to_domain,
        "dkim_domain": dkim_domain,
        "urls": urls,
        "url_domains": url_domains,
        "attachments": atts,
        "has_html_form": has_form,
        "has_html_script": has_script,
        "base64_ratio": base64_ratio,
        "body_text": body_text,
    }

    score, verdict, reasons = score_email(ctx)

    # Normalize dates
    try:
        date_iso = parsedate_to_datetime(date_h).isoformat()
    except Exception:
        date_iso = date_h or ""

    # Prepare CSV row
    row = {
        "file_path": path,
        "subject": subject,
        "from_display_name": from_display,
        "from_address": from_addr,
        "to": "; ".join([addr for _, addr in to_addrs]),
        "date": date_iso,
        "return_path": return_path_addr,
        "reply_to": reply_to_addr,
        "message_id": msg_id,
        "mime_version": mime_ver,
        "spf_result": spf,
        "dkim_result": dkim,
        "dmarc_result": dmarc,
        "dkim_domain": dkim_domain,
        "x_spam_status": x_spam_status,
        "num_received_hops": len(received_chain),
        "received_chain": " | ".join(received_chain),
        "urls_found": " ".join(urls),
        "num_urls": len(urls),
        "url_domains": " ".join(url_domains),
        "attachments": " | ".join(f"{a['name']}({a['mime']},{a['size']}B)" for a in atts),
        "attachment_hashes": " | ".join(f"{a['name']}:{a['sha256']}" for a in atts),
        "body_sha256": body_sha256,
        "has_html_form": has_form,
        "has_html_script": has_script,
        "base64_ratio": f"{base64_ratio:.2f}",
        "suspicious_score": score,
        "verdict": verdict,
        "reasons": "; ".join(reasons),
        "raw_headers": raw_headers,
    }
    return row

def iter_eml_paths(root):
    if os.path.isfile(root):
        yield root
    else:
        for dirpath, _, filenames in os.walk(root):
            for fn in filenames:
                if fn.lower().endswith(".eml"):
                    yield os.path.join(dirpath, fn)



'''
   helper added a built-in benchmarking CLI so you can evaluate (and tune) the scoring thresholds on a labeled corpus, no external libraries required.

'''
POS_MAL = {"malicious", "spam", "phish"}
POS_SUS = {"suspicious", "unknown"}
POS_BEN = {"benign", "ham", "clean"}

def normalize_label(s: str) -> str:
    s = (s or "").strip().lower()
    if s in POS_MAL: return "malicious"
    if s in POS_SUS: return "suspicious"
    if s in POS_BEN: return "benign"
    return ""  # unknown

def load_labels_csv(path):
    """
    Expect columns: file_path,label  (header order doesn't matter).
    Returns dict: {abs_path: normalized_label}
    """
    mapping = {}
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        if "file_path" not in reader.fieldnames or "label" not in reader.fieldnames:
            raise ValueError("LABELS.csv must contain columns: file_path,label")
        for row in reader:
            fp = os.path.abspath((row.get("file_path") or "").strip())
            lab = normalize_label(row.get("label"))
            if fp and lab:
                mapping[fp] = lab
    return mapping

def verdict_from_score(score: int, t_susp: int = 40, t_mal: int = 70) -> str:
    if score >= t_mal: return "malicious"
    if score >= t_susp: return "suspicious"
    return "benign"

def binary_metrics(tp, fp, fn, tn):
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec  = tp / (tp + fn) if (tp + fn) else 0.0
    f1   = 2*prec*rec/(prec+rec) if (prec+rec) else 0.0
    acc  = (tp + tn) / (tp + fp + fn + tn) if (tp+fp+fn+tn) else 0.0
    return prec, rec, f1, acc

def evaluate_binary(rows, labels, threshold, positive_classes={"malicious"}):
    """
    Positive if predicted verdict ∈ positive_classes.
    """
    tp=fp=fn=tn=0
    for r in rows:
        fp_abs = os.path.abspath(r["file_path"])
        true = labels.get(fp_abs, "")
        if not true:  # skip unlabeled
            continue
        pred = verdict_from_score(int(r["suspicious_score"]), threshold, 101)  # only one cutoff
        pred_pos = (pred in positive_classes)
        true_pos = (true in positive_classes)
        if pred_pos and true_pos: tp += 1
        elif pred_pos and not true_pos: fp += 1
        elif not pred_pos and true_pos: fn += 1
        else: tn += 1
    return binary_metrics(tp, fp, fn, tn), (tp, fp, fn, tn)

def evaluate_ternary(rows, labels, t_susp, t_mal):
    """
    Macro-F1 over three classes with two thresholds.
    """
    classes = ["benign", "suspicious", "malicious"]
    cm = {c: Counter() for c in classes}  # cm[true][pred] += 1
    total = 0
    for r in rows:
        fp_abs = os.path.abspath(r["file_path"])
        true = labels.get(fp_abs, "")
        if not true:
            continue
        pred = verdict_from_score(int(r["suspicious_score"]), t_susp, t_mal)
        cm[true][pred] += 1
        total += 1
    # per-class precision/recall/F1
    f1s=[]
    for c in classes:
        tp = cm[c][c]
        fp = sum(cm[t][c] for t in classes if t != c)
        fn = sum(cm[c][p] for p in classes if p != c)
        prec = tp / (tp+fp) if (tp+fp) else 0.0
        rec  = tp / (tp+fn) if (tp+fn) else 0.0
        f1   = 2*prec*rec/(prec+rec) if (prec+rec) else 0.0
        f1s.append(f1)
    macro_f1 = sum(f1s)/len(f1s) if f1s else 0.0
    acc = sum(cm[c][c] for c in classes) / total if total else 0.0
    return macro_f1, acc, cm, total

#End of helper for benchmarking
###

def main():
    ap = argparse.ArgumentParser(description="Offline email phishing/malware analysis for .eml files.")
    ap.add_argument("input", help="Path to a .eml file or a folder containing .eml files (recursively).")
    ap.add_argument("output_csv", help="Path to write the output CSV.")
    ap.add_argument("--extract-attachments", help="Folder to save attachments (optional).", default=None)
    
# NEW: evaluation options
    ap.add_argument("--evaluate", help="Path to LABELS.csv with columns: file_path,label", default=None)
    ap.add_argument("--eval-output", help="Optional path to write per-file predictions CSV.", default=None)
    ap.add_argument("--grid-step", type=int, default=1, help="Threshold step size for search (default 1).")

    args = ap.parse_args()

    
    start_time = time.time()
    start_human = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    rows = []
    count = 0
    for path in iter_eml_paths(args.input):
        try:
            row = analyze_eml(path, extract_dir=args.extract_attachments)
            rows.append(row)
            count += 1
        except Exception as e:
            sys.stderr.write(f"[!] Failed to process {path}: {e}\n")

    if not rows:
        sys.stderr.write("[!] No .eml files processed. Nothing to write.\n")
        sys.exit(2)

    # Determine CSV header order
    fieldnames = [
        "file_path","subject","from_display_name","from_address","to","date",
        "return_path","reply_to","message_id","mime_version",
        "spf_result","dkim_result","dmarc_result","dkim_domain","x_spam_status",
        "num_received_hops","received_chain",
        "urls_found","num_urls","url_domains",
        "attachments","attachment_hashes",
        "body_sha256","has_html_form","has_html_script","base64_ratio",
        "suspicious_score","verdict","reasons",
        "raw_headers"
    ]

    with open(args.output_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, quoting=csv.QUOTE_MINIMAL)
        writer.writeheader()
        for r in rows:
            writer.writerow(r)

#Optional evaluation
    if args.evaluate:
        labels = load_labels_csv(args.evaluate)

        # 1) Binary: Malicious vs Not
        best_bin = {"thr": None, "f1": -1, "prec": 0, "rec": 0, "acc": 0, "cm": (0,0,0,0)}
        for t in range(0, 101, max(1, args.grid_step)):
            (prec, rec, f1, acc), cm = evaluate_binary(rows, labels, t, positive_classes={"malicious"})
            if f1 > best_bin["f1"]:
                best_bin = {"thr": t, "f1": f1, "prec": prec, "rec": rec, "acc": acc, "cm": cm}

        # 2) Ternary: find (t_susp, t_mal) with t_susp < t_mal
        best_tri = {"t_susp": None, "t_mal": None, "macro_f1": -1, "acc": 0, "total": 0}
        for ts in range(0, 100, max(1, args.grid_step)):
            for tm in range(ts+1, 101, max(1, args.grid_step)):
                macro_f1, acc, cm, total = evaluate_ternary(rows, labels, ts, tm)
                if macro_f1 > best_tri["macro_f1"]:
                    best_tri.update({"t_susp": ts, "t_mal": tm, "macro_f1": macro_f1, "acc": acc})

    
    # Print summary
        print("\n=== Evaluation Summary ===")
        print(f"Labeled items matched: {sum(1 for r in rows if os.path.abspath(r['file_path']) in labels)}")
        print("\n[Binary] Positive=Malicious")
        print(f" Best threshold       : {best_bin['thr']}")
        print(f" Precision / Recall   : {best_bin['prec']:.3f} / {best_bin['rec']:.3f}")
        print(f" F1 / Accuracy        : {best_bin['f1']:.3f} / {best_bin['acc']:.3f}")

        print("\n[Ternary] Classes=Benign/Suspicious/Malicious")
        print(f" Best thresholds      : Suspicious≥{best_tri['t_susp']}, Malicious≥{best_tri['t_mal']}")
        print(f" Macro-F1 / Accuracy  : {best_tri['macro_f1']:.3f} / {best_tri['acc']:.3f}")

        # Optional: write per-file predictions with suggested ternary thresholds
        if args.eval_output:
            t_susp = best_tri["t_susp"] if best_tri["t_susp"] is not None else 40
            t_mal  = best_tri["t_mal"]  if best_tri["t_mal"]  is not None else 70
            out_fields = ["file_path","score","predicted_verdict","label","is_correct"]
            with open(args.eval_output, "w", newline="", encoding="utf-8") as ef:
                ew = csv.DictWriter(ef, fieldnames=out_fields)
                ew.writeheader()
                for r in rows:
                    fp_abs = os.path.abspath(r["file_path"])
                    label = labels.get(fp_abs, "")
                    pred = verdict_from_score(int(r["suspicious_score"]), t_susp, t_mal)
                    is_corr = (label == pred) if label else ""
                    ew.writerow({
                        "file_path": r["file_path"],
                        "score": r["suspicious_score"],
                        "predicted_verdict": pred,
                        "label": label,
                        "is_correct": is_corr
                    })
            print(f"[+] Wrote evaluation predictions to {args.eval_output}")

    end_time = time.time()
    end_human = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    elapsed = end_time - start_time

    print(f"[+] Wrote {len(rows)} result(s) to {args.output_csv}")
    print(f"[+] Start time : {start_human}")
    print(f"[+] End time   : {end_human}")
    print(f"[+] Elapsed    : {elapsed:.2f} seconds")
    print(f"[+] Files processed: {count}")
    if count:
        print(f"[+] Avg per email: {elapsed / count:.4f} s/email")



if __name__ == "__main__":
    main()

