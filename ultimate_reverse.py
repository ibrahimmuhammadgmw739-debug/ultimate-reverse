print("""
╔══════════════════════════════════════════╗
║   ������ Ultimate Reverse Analyzer v1.0      ║
╚══════════════════════════════════════════╝
Analyzes JS, JSON, HTML & config files
for endpoints, secrets, and logic flaws.
Coded by imreal laden ������
""")

import http.client
http.client._MAXHEADERS = 1000  # allow up to 1000 headers instead of 100

import requests
import re
import base64
import json
import xml.etree.ElementTree as ET
import warnings

from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning
from colorama import Fore, Style, init

warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
init(autoreset=True)

def prompt_target():
      print(Fore.CYAN + "\nAdvanced Universal File Inspector")
      url = input(Fore.YELLOW + "Enter target URL: ").strip()

# Sanitize and fix common mistakes
    if url.startswith("httpsttps://") or url.startswith("htttps://"):
              url = url.replace("httpsttps://", "https://").replace("htttps://", "https://")

    # Auto-add https:// if user forgot the scheme
    if not url.startswith("http://") and not url.startswith("https://"):
              url = "https://" + url

    return url

def get_content(url):
      try:
                headers = {
                              "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                                            "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
                }
                resp = requests.get(url, headers=headers, allow_redirects=True, timeout=90)
                resp.raise_for_status()
                return resp.text, resp.headers.get('Content-Type', '')
except Exception as e:
        print(Fore.RED + f"  [!] Failed to fetch {url}: {e}")
        return None, None

def extract_base64(content): return re.findall(r'([A-Za-z0-9+/=]{20,})', content)

def decode_base64(encoded_list):
      decoded = []
      for item in encoded_list:
        try:
                      decoded_str = base64.b64decode(item + "==").decode('utf-8')
                      if any(c.isprintable() for c in decoded_str):
                                        decoded.append((item, decoded_str.strip()))
                                except:
                                              continue
                                      return decoded

def extract_from_html(content):
      soup = BeautifulSoup(content, 'html.parser')
    findings = {
              "Forms": [form.get('action') for form in soup.find_all('form') if form.get('action')],
                "Script Sources": [script.get('src') for script in soup.find_all('script') if script.get('src')],
        "Links": [a.get('href') for a in soup.find_all('a') if a.get('href')],
                "Image Sources": [img.get('src') for img in soup.find_all('img') if img.get('src')],
        "Params": re.findall(r'[?&](\w+)=', content),
                "Secrets": re.findall(
            r'(?:API_KEY|apiKey|secret|token|auth|jwt)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_.]+)',
                              content,
                                              re.IGNORECASE
),
        "Base64 Strings": extract_base64(content),
        "XHRs": re.findall(r'open\(["\'](?:GET|POST)?["\'],\s*["\'](.*?)["\']', content),
              "fetch()": re.findall(r'fetch\(["\'](.*?)["\']', content),
        "Axios POST": re.findall(r'axios\.post\(["\'](.*?)["\']', content),
                                          "Axios GET": re.findall(r'axios\.get\(["\'](.*?)["\']', content),
                                "GraphQL": re.findall(r'/graphql["\']?', content, re.IGNORECASE),
        "Hidden Params": re.findall(r'name=["\'](.*?)["\'].*type=["\']hidden["\']', content)
}
            return findings

def extract_from_json(content):
    try:
        data = json.loads(content)
        flat_keys = []

        def flatten(obj):
            if isinstance(obj, dict):
                        for k, v in obj.items():
                            flat_keys.append(k)
                    flatten(v)
elif isinstance(obj, list):
                for i in obj:
                                      flatten(i)

        flatten(data)

        return {
                      "Keys": list(set(flat_keys)),
                      "Secrets": re.findall(
                                        r'(?:API_KEY|apiKey|secret|token|auth|jwt)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_.]+)',
                                        content,
                                        re.IGNORECASE
                      ),
                      "Base64 Strings": extract_base64(content)
        }
    except:
        return {}

def extract_from_xml(content):
      import xml.etree.ElementTree as ET

    urls = []
    tags = set()

    try:
              root = ET.fromstring(content)
              for elem in root.iter():
                            tags.add(elem.tag)
                            if elem.tag.endswith('loc') and elem.text:
                                              urls.append(elem.text.strip())
    except Exception as e:
              print(f"XML parsing error: {e}")

    return {
              "Tags": list(tags),
              "Discovered URLs": urls
    }

def extract_from_raw_text(content):
      return {
                "URLs": re.findall(r'https?://[\w./?=&%-]+', content),
                "Base64 Strings": extract_base64(content),
                            "Params": re.findall(r'[?&](\w+)=', content),
                "Secrets": re.findall(
                              r'(?:API_KEY|apiKey|secret|token|auth|jwt)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_.]+)',
                             content,
                              re.IGNORECASE
                )}
  def extract_from_js(content):


        urls = re.findall(r'https?://[^\s"\'<>]+', content)
        base64s = extract_base64(content)

    fetch_urls = re.findall(r'fetch\((["\'])(.*?)\1', content)
    axios_calls = re.findall(r'axios\.(get|post|put|delete)\((["\'])(.*?)\2', content)
    graphql_endpoints = re.findall(r'/api/[\w/]*graphql', content)

    # Match common param=value patterns
    params = re.findall(r'[?&]([a-zA-Z0-9_]+)=', content)

    # Secrets and tokens (basic heuristic)
    secrets = re.findall(r'(?:api[_-]?key|token|secret)[\'"]?\s*[:=]\s*[\'"]?([a-zA-Z0-9_\-]{8,})', content, re.IGNORECASE)

    # Match resource types (images, fonts, CSS)
    resources = re.findall(r'(https?://[^\s"\'<>]+\.(?:png|jpg|jpeg|gif|svg|webp|woff2?|ttf|eot|css|js))', content)

    return {
              "Fetch URLs": list(set([f[1] for f in fetch_urls])),
              "Axios URLs": list(set([call[2] for call in axios_calls])),
              "GraphQL Endpoints": list(set(graphql_endpoints)),
              "All URLs": list(set(urls)),
              "Base64 Strings": list(set(base64s)),
              "Secrets / Tokens": list(set(secrets)),
              "Params": list(set(params)),
              "Resource Files": list(set(resources)),
    }

def print_tree(url, ctype, findings):
      print(Fore.GREEN + f"\n������ URL: {url}")
      print(f"├── Type: {ctype if ctype else 'Unknown'}")

    for key in findings:
              values = findings[key]
              if values:
                            branch = f"├── {key}:" if key != list(findings)[-1] else f"└── {key}:"
                            print(branch)
                            for val in values:
                                              if isinstance(val, tuple):
                                                                    print(f"│   └── {val[0]}  →  {val[1]}")
                                              else:
                                                                    print(f"│   └── {val}")

    decoded = decode_base64(findings.get("Base64 Strings", []))
    if decoded:
              print(f"└── Decoded Base64:")
              for pair in decoded:
                            print(f"    └── {pair[0]}  →  {pair[1]}")

def analyze_content(url, content, ctype):
      if not ctype:
                ctype = ""

    url_lower = url.lower()

    # Create grouped file extension checks
    html_exts = (".html", ".htm", ".php", ".asp", ".aspx", ".jsp", ".ejs")
    js_exts = (".js",)
    json_exts = (".json",)
    xml_exts = (".xml",)
    text_exts = (".txt", ".log", ".env", ".conf", ".cfg", ".ini", ".md", ".yaml", ".yml", ".csv", ".py", ".rb", ".java", ".go")

    if "html" in ctype or url_lower.endswith(html_exts):
              return extract_from_html(content)
elif "javascript" in ctype or url_lower.endswith(js_exts):
          return extract_from_js(content)
elif "json" in ctype or url_lower.endswith(json_exts):
          return extract_from_json(content)
elif "xml" in ctype or url_lower.endswith(xml_exts):
          return extract_from_xml(content)
elif "text" in ctype or url_lower.endswith(text_exts):
          return extract_from_raw_text(content)
    else:
              print(Fore.MAGENTA + "  [?] Unknown content type, using raw text extraction...")
              return extract_from_raw_text(content)

def main():
      url = prompt_target()
      content, ctype = get_content(url)
      if not content:
                return

    findings = analyze_content(url, content, ctype)
    print_tree(url, ctype, findings)
if __name__ == "__main__":
      main()



