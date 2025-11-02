import os
import sys
import json
from textwrap import dedent
import requests
import dotenv
import re

# Local import when run inside repo
try:
    import download_data
except ImportError:
    download_data = None


def load_env():
    dotenv.load_dotenv()
    api_key = os.getenv("RESEND_API_KEY")
    send_to = os.getenv("SEND_TO")
    send_from = os.getenv("SEND_FROM") or os.getenv("NOTIFY_FROM") or "no-reply@example.com"
    if not api_key:
        raise SystemExit("Missing RESEND_API_KEY in environment.")
    if not send_to:
        raise SystemExit("Missing SEND_TO in environment.")
    return api_key, send_to, send_from


def ensure_member_names(csv_path: str = "member_names.csv"):
    if os.path.exists(csv_path):
        return csv_path
    # If names file is missing but raw exists, regenerate; else call helper if present
    if download_data:
        try:
            download_data.get_names_only_member_data()
        except Exception as e:
            print(f"Failed to generate member names via download_data: {e}")
    if not os.path.exists(csv_path):
        raise SystemExit(f"Names file '{csv_path}' not found and could not be generated.")
    return csv_path


def read_names(csv_path: str = "member_names.csv"):
    names = []
    try:
        with open(csv_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and line.lower() != "nev":  # skip header if present
                    names.append(line)
    except FileNotFoundError:
        raise SystemExit(f"File '{csv_path}' not found.")
    if not names:
        raise SystemExit("No names found in member_names.csv")
    # Deduplicate preserving first occurrence, then sort case-insensitively
    dedup = []
    seen = set()
    for n in names:
        if n not in seen:
            seen.add(n)
            dedup.append(n)
    # Hungarian alphabet ordering including digraphs
    # Order reference: A Á B C Cs D Dz Dzs E É F G Gy H I Í J K L Ly M N Ny O Ó Ö Ő P Q R S Sz T Ty U Ú Ü Ű V W X Y Z Zs
    # We'll map each token (single letter or recognized digraph) to its rank.
    hun_order = [
        'a', 'á', 'b', 'c', 'cs', 'd', 'dz', 'dzs', 'e', 'é', 'f', 'g', 'gy', 'h', 'i', 'í', 'j', 'k', 'l', 'ly', 'm',
        'n', 'ny', 'o', 'ó', 'ö', 'ő', 'p', 'q', 'r', 's', 'sz', 't', 'ty', 'u', 'ú', 'ü', 'ű', 'v', 'w', 'x', 'y', 'z',
        'zs'
    ]
    rank = {v: i for i, v in enumerate(hun_order)}
    digraphs = ['dzs', 'cs', 'dz', 'gy', 'ly', 'ny', 'sz', 'ty', 'zs']
    digraph_re = re.compile('|'.join(sorted(digraphs, key=len, reverse=True)))

    def tokenize(name: str):
        # Lowercase with accents preserved
        s = name.lower()
        tokens = []
        i = 0
        while i < len(s):
            # Try longest digraph match first
            matched = None
            for dg in digraphs:
                if s.startswith(dg, i):
                    matched = dg
                    break
            if matched:
                tokens.append(matched)
                i += len(matched)
            else:
                tokens.append(s[i])
                i += 1
        return tokens

    def sort_key(name: str):
        tokens = tokenize(name)
        return [rank.get(t, 999) for t in tokens] + [len(tokens)]

    dedup.sort(key=sort_key)
    return dedup


def build_email_html(names):
    items = "".join(f"<li>{name}</li>" for name in names)
    return dedent(f"""
    <div style='font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;line-height:1.5'>
      <h2 style='margin:0 0 .5rem'>Tagnyilvántartás - Nevek lista</h2>
      <p style='margin:.25rem 0'>Összesen <b>{len(names)}</b> név szerepel a listában.</p>
      <ul style='margin:.5rem 0 0 1.25rem; padding:0'>
        {items}
      </ul>
      <hr style='border:none;border-top:1px solid #e5e7eb;margin:1rem 0'>
      <p style='font-size:12px;color:#6b7280;margin:0'>Automatikus üzenet - kérjük ne válaszoljon rá.</p>
    </div>
    """)


def send_email(api_key: str, send_from: str, send_to: str, names):
    url = "https://api.resend.com/emails"
    subject = "Tagnyilvántartás - Nevek lista"
    html = build_email_html(names)
    payload = {
        "from": send_from,
        "to": send_to,
        "subject": subject,
        "html": html,
    }
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    r = requests.post(url, headers=headers, data=json.dumps(payload), timeout=30)
    if r.status_code not in (200, 202):
        print(f"Email sending failed: {r.status_code} {r.text}")
        raise SystemExit(1)
    print("Email sent successfully.")


def main():
    api_key, send_to, send_from = load_env()
    ensure_member_names()
    names = read_names()
    send_email(api_key, send_from, send_to, names)


if __name__ == "__main__":
    main()
