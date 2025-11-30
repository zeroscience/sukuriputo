#!/usr/bin/env python3
"""
nginx-conf-qs (NCQS - Nginx Configuration Quick Scan) is a Python-based static security scanner
designed to analyze Nginx configuration files and related infrastructure code in a directory,
providing a thorough audit of potential misconfigurations, weak cryptography, exposed secrets,
and risky deployment patterns. It supports scanning individual .conf files, recursive includes,
and additional modules via a pluggable system. Built-in checks detect weak SSL/TLS protocols,
weak ciphers, missing certificates, exposed autoindex, and proxy misconfigurations.

Additional modules include:
- k8s_checks for Kubernetes ingress detection, TLS and annotation issues;
- aws_checks for AWS load balancer, CloudFront/S3 origin, and public EC2 exposure;
- yaml_scanner for YAML-based files, identifying exposed secrets, NodePort risks, WireGuard/VPN
configs, and Kubernetes ingress misconfigurations.

Users can invoke the scanner with -p <path_to_directory> to scan a folder, and -m <module_name>
to include extra modules. The tool outputs results in HTML, JSON, and CSV formats with color-coded
severity, domains, locations, and proxies, including a dark/light toggle in HTML, and aggregates
findings per file, making it ideal for auditing private repositories, CI/CD pipelines, and deployment
manifests.

nginx-conf-qs (Nginx Configuration Quick Scan) - single-file scanner with pluggable rule modules.

Usage example:
    ./nginx-conf-qs.py -p /etc/nginx -r reports -m yaml_scanner -v

Author: Gjoko Krstic
Inspiration: Gixy
Powered by: Silly Security - https://www.sillysec.com
Version: 16.11-43g (Codename: Delfina)

"""

from __future__ import annotations
import os
import sys
import re
import glob
import argparse
import json
import csv
import html
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Tuple, Optional

# Optional cryptography parsing for key inspection
try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import rsa
    CRYPTO_AVAILABLE = True
except Exception:
    CRYPTO_AVAILABLE = False

# === Config / constants ===
SCRIPT_NAME = "nginx-conf-qs"
TITLE_HTML = "Nginx Configuration Scan Report - Zero Science Lab"
FOOTER_ATTRIBUTION = "Powered by Zero Science Lab - https://www.zeroscience.mk — Author: Gjoko Krstic. Version: 16.11-43g"
MODULES_DIR = "modules"
DEFAULT_RESULTS_DIR = "reports"

SEVERITY_ORDER = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
SEVERITY_COLOR = {
    "HIGH": "#ff4d4d",
    "MEDIUM": "#ffae42",
    "LOW": "#ffd24d",
    "INFO": "#94d3a2"
}

# === ASCII banner for help/usage ===
BANNER = r"""                         
 _____ _____ _____ _____ 
|   | |     |     |   __|
| | | |   --|  |  |__   |
|_|___|_____|__  _|_____|
               |__|
(Nginx Configuration Quick Scan)
"""

# === Utilities ===

def utc_ts():
    return datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")

def ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)

def read_file(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception:
        return ""

def write_file(path: str, data: str):
    with open(path, "w", encoding="utf-8") as f:
        f.write(data)

# === Minimal block-aware parser (heuristic) ===

directive_line_re = re.compile(r'^\s*([A-Za-z_]+)\s*(.*?)\s*;(?:\s*#.*)?$')
include_re = re.compile(r'^\s*include\s+(.*?);', re.IGNORECASE)

def tokenize_nginx(text: str) -> List[Tuple[int,str]]:
    out = []
    for idx, raw in enumerate(text.splitlines()):
        lineno = idx + 1
        line = raw
        if '#' in line:
            pos = line.find('#')
            prefix = line[:pos]
            if prefix.count('"') % 2 == 0 and prefix.count("'") % 2 == 0:
                line = prefix
        if line.strip() == '':
            continue
        out.append((lineno, line.rstrip()))
    return out

def parse_blocks(text: str, src_path: str = "<string>") -> List[Dict]:
    """
    Parse into nested blocks. Each block: {type, args, start, end, children, directives, parent}
    This is a heuristic parser good for most real-world nginx configs.
    """
    tokens = tokenize_nginx(text)
    root = {"type":"root","args":"","start":1,"end":None,"children":[],"directives":[],"parent":None}
    stack = [root]
    for lineno, line in tokens:
        # opening block
        mopen = re.match(r'^\s*([^{;]+)\{\s*$', line)
        if mopen:
            header = mopen.group(1).strip()
            parts = header.split(None, 1)
            btype = parts[0]
            args = parts[1] if len(parts) > 1 else ""
            blk = {"type": btype, "args": args, "start": lineno, "end": None, "children": [], "directives": [], "parent": stack[-1]}
            stack[-1]["children"].append(blk)
            stack.append(blk)
            continue
        # closing
        if re.match(r'^\s*}\s*$', line):
            if len(stack) > 1:
                stack[-1]["end"] = lineno
                stack.pop()
            continue
        # single-line block like: location / { proxy_pass ...; }
        single_block = re.match(r'^\s*([^{]+)\{\s*(.*?)\s*\}\s*$', line)
        if single_block:
            header = single_block.group(1).strip()
            inner = single_block.group(2)
            parts = header.split(None, 1)
            btype = parts[0]
            args = parts[1] if len(parts) > 1 else ""
            blk = {"type": btype, "args": args, "start": lineno, "end": lineno, "children": [], "directives":[],"parent": stack[-1]}
            # parse inner directives
            for part in re.split(r';\s*', inner):
                if part.strip():
                    mm = re.match(r'^\s*([A-Za-z_]+)\s+(.*)$', part.strip())
                    if mm:
                        blk["directives"].append((lineno, mm.group(1), mm.group(2).strip()))
            stack[-1]["children"].append(blk)
            continue
        # directive
        md = directive_line_re.match(line)
        if md:
            name = md.group(1)
            val = md.group(2).strip()
            stack[-1]["directives"].append((lineno, name, val))
            continue
        # ignore other lines
    return root["children"]

def flatten_blocks(blocks: List[Dict]) -> List[Dict]:
    out = []
    def walk(node, context):
        for (lineno, name, val) in node.get("directives", []):
            out.append({"lineno": lineno, "name": name, "value": val, "context": context.copy(), "block": node})
        for c in node.get("children", []):
            walk(c, context + [f"{c['type']} {c['args']}".strip()])
    for b in blocks:
        walk(b, [f"{b['type']} {b['args']}".strip()])
    return out

def resolve_includes(file_path: str, text: str) -> List[str]:
    ddir = os.path.dirname(file_path) or "."
    includes = []
    for m in include_re.finditer(text):
        raw = m.group(1).strip().strip('"\'')
        if not os.path.isabs(raw):
            candidate = os.path.join(ddir, raw)
        else:
            candidate = raw
        expanded = glob.glob(candidate, recursive=True)
        if expanded:
            includes.extend(sorted(set(expanded)))
        else:
            includes.append(candidate)
    return includes

# === Issue structure helpers ===

def add_issue(coll: List[Dict], severity: str, title: str, description: str, lineno: Optional[int]=None,
              snippet: Optional[str]=None, rule: Optional[str]=None, context: Optional[List[str]]=None):
    coll.append({
        "severity": severity,
        "title": title,
        "description": description,
        "lineno": lineno,
        "snippet": snippet,
        "rule": rule,
        "context": context or []
    })

def severity_filter_ok(s: str, min_sev: str) -> bool:
    return SEVERITY_ORDER[s] >= SEVERITY_ORDER[min_sev]

# === Built-in checks (heuristics) ===

def check_server_tokens(directives, issues):
    found=False
    for d in directives:
        if d['name']=='server_tokens':
            found=True
            if d['value'].lower().startswith('on'):
                add_issue(issues,"HIGH","server_tokens is on","server_tokens may reveal version. Set 'server_tokens off;'.",d['lineno'],d['value'],'server_tokens:on',d.get('context'))
            return
    if not found:
        add_issue(issues,"MEDIUM","server_tokens not set","Recommend 'server_tokens off;'.",None,None,'server_tokens:missing',None)

def check_ssl_protocols(directives, issues):
    for d in directives:
        if d['name']=='ssl_protocols':
            v = d['value'].lower()
            if ('tlsv1' in v and 'tlsv1.2' not in v and 'tlsv1.3' not in v):
                add_issue(issues,"HIGH","Weak TLS protocols configured","ssl_protocols includes TLSv1 or TLSv1.1. Use TLSv1.2+.",d['lineno'],d['value'],'ssl_protocols:weak',d.get('context'))
            elif 'tlsv1' in v and ('tlsv1.2' in v or 'tlsv1.3' in v):
                add_issue(issues,"LOW","Legacy TLS protocol allowed","Remove legacy TLS protocols.",d['lineno'],d['value'],'ssl_protocols:legacy',d.get('context'))
            return
    add_issue(issues,"MEDIUM","ssl_protocols not configured","Set 'ssl_protocols TLSv1.2 TLSv1.3;'.",None,None,'ssl_protocols:missing',None)

def check_ssl_ciphers(directives, issues):
    for d in directives:
        if d['name']=='ssl_ciphers':
            v = d['value'].lower()
            weak = ['rc4','des','3des','md5','null','export']
            found = [t for t in weak if t in v]
            if found:
                add_issue(issues,"HIGH","Weak ciphers configured","ssl_ciphers contains weak algos: "+', '.join(found),d['lineno'],d['value'],'ssl_ciphers:weak',d.get('context'))
            return
    add_issue(issues,"LOW","ssl_ciphers not configured","Consider setting strong cipher suites.",None,None,'ssl_ciphers:missing',None)

def check_ssl_prefer_server_ciphers(directives, issues):
    for d in directives:
        if d['name']=='ssl_prefer_server_ciphers':
            if d['value'].lower().startswith('off'):
                add_issue(issues,"MEDIUM","ssl_prefer_server_ciphers is off","Set 'ssl_prefer_server_ciphers on;'.",d['lineno'],d['value'],'ssl_prefer_server_ciphers:off',d.get('context'))
            return
    add_issue(issues,"LOW","ssl_prefer_server_ciphers not set","Consider 'ssl_prefer_server_ciphers on;'.",None,None,'ssl_prefer_server_ciphers:missing',None)

def check_hsts_and_headers(directives, issues):
    headers = {}
    for d in directives:
        if d['name']=='add_header':
            parts = re.split(r'\s+', d['value'], 1)
            if parts:
                n = parts[0].strip('"\'').lower()
                headers[n] = d
    if 'strict-transport-security' not in headers:
        add_issue(issues,"HIGH","HSTS not configured","Add Strict-Transport-Security header for HTTPS sites.",None,None,'hsts:missing',None)
    for hdr, sev, desc in (('x-frame-options','MEDIUM','Missing X-Frame-Options'),('x-content-type-options','HIGH','Missing X-Content-Type-Options: nosniff'),('content-security-policy','MEDIUM','Missing Content-Security-Policy')):
        if hdr not in headers:
            add_issue(issues,sev,f"{hdr} header missing",desc,None,None,f'header:{hdr}:missing',None)

def check_autoindex(directives, issues):
    for d in directives:
        if d['name']=='autoindex' and d['value'].lower().startswith('on'):
            add_issue(issues,"HIGH","autoindex enabled","autoindex on; may leak directory listings.",d['lineno'],d['value'],'autoindex:on',d.get('context'))

def check_client_max_body(directives, issues):
    found=False
    for d in directives:
        if d['name']=='client_max_body_size':
            found=True
            try:
                v = d['value'].lower()
                if v.endswith('m'):
                    num = int(v[:-1]) * 1024 * 1024
                elif v.endswith('k'):
                    num = int(v[:-1]) * 1024
                elif v.endswith('g'):
                    num = int(v[:-1]) * 1024 * 1024 * 1024
                else:
                    num = int(re.sub(r'\D','', v))
                if num > 100*1024*1024:
                    add_issue(issues,"LOW","Large client_max_body_size",f"client_max_body_size is {d['value']}. Consider lowering.",d['lineno'],d['value'],'client_max_body_size:large',d.get('context'))
            except Exception:
                pass
    if not found:
        add_issue(issues,"LOW","client_max_body_size not set","Consider setting limits to prevent large uploads.",None,None,'client_max_body_size:missing',None)

def check_proxy_pass_unsafe(directives, issues):
    for d in directives:
        if d['name']=='proxy_pass':
            val = d['value'].lower()
            if '$request_uri' in val or '$request' in val:
                add_issue(issues,"HIGH","proxy_pass uses request variable","Using $request_uri or $request may be unsafe.",d['lineno'],d['value'],'proxy_pass:vars',d.get('context'))
            if re.search(r'\$http_[a-z0-9_]+', val):
                add_issue(issues,"HIGH","proxy_pass depends on HTTP header variable","proxy_pass uses header-derived variable.",d['lineno'],d['value'],'proxy_pass:http_var',d.get('context'))

def check_alias_usage(directives, issues):
    for d in directives:
        if d['name']=='alias':
            add_issue(issues,"MEDIUM","Found 'alias' directive","Ensure alias trailing slash and location matching are correct.",d['lineno'],d['value'],'alias:found',d.get('context'))

def check_try_files(directives, issues):
    for d in directives:
        if d['name']=='try_files':
            if 'index.php' in d['value'].lower() and '=' not in d['value']:
                add_issue(issues,"LOW","try_files may cause unintended execution","Check try_files fallback order.",d['lineno'],d['value'],'try_files:check',d.get('context'))

def check_limit_except_presence(all_text, issues):
    if 'limit_except' not in all_text:
        add_issue(issues,"LOW","No limit_except directives","Consider using 'limit_except' in sensitive locations.",None,None,'limit_except:missing',None)

def check_resolver(directives, issues):
    for d in directives:
        if d['name']=='resolver':
            if '8.8.8.8' in d['value'] or '1.1.1.1' in d['value']:
                add_issue(issues,"INFO","Public DNS configured in resolver",f"Resolver uses {d['value']}. Verify intention.",d['lineno'],d['value'],'resolver:public',d.get('context'))

def check_add_header_redefinition(directives, issues):
    hdrs={}
    for d in directives:
        if d['name']=='add_header':
            n = d['value'].split(None,1)[0].strip('"\'').lower()
            hdrs.setdefault(n, []).append(d)
    for k,v in hdrs.items():
        if len(v)>1:
            add_issue(issues,"LOW",f"Header possibly redefined: {k}",f"Multiple add_header for {k} found.",v[0]['lineno'],v[0]['value'],'add_header:multidef',v[0].get('context'))

def examine_cert_and_key(directives, file_dir, issues):
    certs=[]
    keys=[]
    for d in directives:
        if d['name']=='ssl_certificate':
            certs.append((d['lineno'], d['value'], d.get('context')))
        if d['name']=='ssl_certificate_key':
            keys.append((d['lineno'], d['value'], d.get('context')))
    for lineno, kp, ctx in keys:
        kp_clean = kp.strip().strip('"\'')
        candidate = kp_clean if os.path.isabs(kp_clean) else os.path.join(file_dir, kp_clean)
        if os.path.exists(candidate):
            try:
                content = read_file(candidate)
                if CRYPTO_AVAILABLE:
                    try:
                        key = serialization.load_pem_private_key(content.encode('utf-8'), password=None, backend=default_backend())
                        if isinstance(key, rsa.RSAPrivateKey):
                            bits = key.key_size
                            if bits < 2048:
                                add_issue(issues,"HIGH","Weak RSA private key",f"Private key at {candidate} appears to be RSA {bits} bits. Use 2048+.",lineno,kp,'ssl_key:rsa_small',ctx)
                            else:
                                add_issue(issues,"INFO","RSA key size detected",f"Private key at {candidate} is RSA {bits} bits.",lineno,kp,'ssl_key:rsa',ctx)
                        else:
                            add_issue(issues,"INFO","Private key parsed",f"Private key at {candidate} parsed (non-RSA).",lineno,kp,'ssl_key:other',ctx)
                    except Exception as e:
                        add_issue(issues,"LOW","Could not parse private key with cryptography",f"Parsing {candidate} failed: {e}",lineno,kp,'ssl_key:parse_fail',ctx)
                else:
                    add_issue(issues,"INFO","Private key referenced (parsing unavailable)",f"{candidate} exists but 'cryptography' library not installed; cannot parse key strength.",lineno,kp,'ssl_key:unparsed',ctx)
            except Exception as e:
                add_issue(issues,"LOW","Unable to read key file",f"Could not read {candidate}: {e}",lineno,kp,'ssl_key:read_fail',ctx)
        else:
            add_issue(issues,"MEDIUM","Referenced private key not found",f"Key path {candidate} referenced but file not present on disk.",lineno,kp,'ssl_key:notfound',ctx)

# === Scan functions (file-level with include expansion) ===

def scan_file(file_path: str, seen_includes: set, verbose: bool=False) -> Dict:
    result = {"content":"","directives":[],"issues":[],"servers":[],"includes":[]}
    file_text = read_file(file_path)
    if not file_text:
        return result
    result["content"] = file_text
    blocks = parse_blocks(file_text, src_path=file_path)
    flat = flatten_blocks(blocks)
    # collect directives
    directive_dicts = []
    # collect server meta
    servers_meta = []
    lines = file_text.splitlines()
    def extract_raw_block(b):
        if b.get('start') and b.get('end'):
            s = max(1, b['start'])-1
            e = min(len(lines), b['end'])
            return "\n".join(lines[s:e])
        return ""
    def walk_blocks_for_meta(bs, ctx):
        for b in bs:
            ctx_local = ctx + [f"{b['type']} {b['args']}".strip()]
            local_directives=[]
            for lineno,name,val in b.get('directives', []):
                local_directives.append({"lineno":lineno,"name":name,"value":val,"context":ctx_local})
            if b['type']=='server':
                servers_meta.append({"server_names":[d['value'] for d in local_directives if d['name']=='server_name'],
                                     "locations":[c['args'] for c in b.get('children',[]) if c['type']=='location'],
                                     "proxy_pass":[d['value'] for d in local_directives if d['name']=='proxy_pass'],
                                     "raw": extract_raw_block(b),
                                     "directives": local_directives})
            for ld in local_directives:
                directive_dicts.append(ld)
            walk_blocks_for_meta(b.get('children',[]), ctx_local)
    walk_blocks_for_meta(blocks, [])
    # flatten top-level directives
    for d in flat:
        directive_dicts.append({"lineno": d['lineno'], "name": d['name'], "value": d['value'], "context": d['context']})
    # deduplicate by (lineno,name,value)
    seen=set(); cleaned=[]
    for d in directive_dicts:
        key=(d['lineno'], d['name'], d['value'])
        if key in seen:
            continue
        seen.add(key)
        cleaned.append(d)
    issues=[]
    # run built-in checks
    check_server_tokens(cleaned, issues)
    check_ssl_protocols(cleaned, issues)
    check_ssl_ciphers(cleaned, issues)
    check_ssl_prefer_server_ciphers(cleaned, issues)
    check_hsts_and_headers(cleaned, issues)
    check_autoindex(cleaned, issues)
    check_client_max_body(cleaned, issues)
    # server-specific listen 80 check
    server_blocks_for_check = []
    for s in servers_meta:
        server_blocks_for_check.append({"directives": s['directives'], "raw": s['raw'], "context": ["server"]})
    # simple check: if listen 80 and no redirect
    for sb in server_blocks_for_check:
        has80 = any(d['name']=='listen' and re.search(r'\b80\b', d['value']) for d in sb['directives'])
        if has80:
            raw = (sb.get('raw') or "").lower()
            if 'return 301' not in raw and 'rewrite ' not in raw and 'return 302' not in raw and 'return 308' not in raw:
                add_issue(issues,"MEDIUM","Plain HTTP server without redirect","listen 80 in server without redirect to HTTPS.",None,None,'listen:80:noredirect',["server"])
    check_proxy_pass_unsafe(cleaned, issues)
    check_alias_usage(cleaned, issues)
    check_try_files(cleaned, issues)
    check_limit_except_presence(file_text, issues)
    check_resolver(cleaned, issues)
    check_add_header_redefinition(cleaned, issues)
    try:
        examine_cert_and_key(cleaned, os.path.dirname(file_path) or ".", issues)
    except Exception:
        pass
    result["directives"]=cleaned
    result["issues"]=issues
    result["servers"]=servers_meta
    # includes
    includes=resolve_includes(file_path, file_text)
    result["includes"]=[]
    for inc in includes:
        if os.path.exists(inc):
            if inc not in seen_includes:
                seen_includes.add(inc)
                result["includes"].append(inc)
        else:
            result["includes"].append(inc)
    return result

def collect_conf_files(root_path: str) -> List[str]:
    if os.path.isfile(root_path):
        return [root_path]
    res=[]
    for dirpath, _, filenames in os.walk(root_path):
        for fn in filenames:
            if fn.endswith(".conf") or fn=="nginx.conf":
                res.append(os.path.join(dirpath, fn))
    res.sort()
    return res

def full_scan(root_path: str, verbose: bool=False) -> Dict[str, Dict]:
    conf_files = collect_conf_files(root_path)
    results={}
    seen_includes=set()
    queue=list(conf_files)
    idx=0
    while idx < len(queue):
        fp = queue[idx]; idx+=1
        if not os.path.exists(fp):
            if verbose:
                print("Skipping missing:", fp)
            continue
        if fp in results:
            continue
        if verbose:
            print("Scanning:", fp)
        res = scan_file(fp, seen_includes, verbose)
        results[fp] = res
        for inc in res.get("includes", []):
            expanded = glob.glob(inc, recursive=True) if any(ch in inc for ch in ['*','?','[']) else ([inc] if os.path.exists(inc) else [])
            if expanded:
                for e in expanded:
                    if e not in queue and os.path.exists(e):
                        queue.append(e)
            else:
                if os.path.exists(inc) and inc not in queue:
                    queue.append(inc)
    return results

# === Pluggable modules loader ===

def ensure_modules_dir():
    ensure_dir(MODULES_DIR)
    # create example module if missing
    example_path = os.path.join(MODULES_DIR, "example_module.py")
    if not os.path.exists(example_path):
        example_source = '''"""
Example module for nginx-conf-qs
Place additional modules into the "modules/" directory. Module must expose a function:
    def run(file_path: str, text: str, directives: List[Dict]) -> List[Dict]:
which returns a list of issues in the same format used by the main scanner:
    {
      "severity": "HIGH"|"MEDIUM"|"LOW"|"INFO",
      "title": "...",
      "description": "...",
      "lineno": 123,           # optional
      "snippet": "line text",  # optional
      "rule": "example:rule",
      "context": ["server default", "location /"]
    }
This example flags use of "ssl_session_cache off" as INFO.
"""
def run(file_path, text, directives):
    issues = []
    for d in directives:
        if d['name'] == 'ssl_session_cache' and 'off' in d['value'].lower():
            issues.append({
                "severity": "INFO",
                "title": "ssl_session_cache disabled",
                "description": "ssl_session_cache is set to off; enabling it may improve SSL/TLS performance.",
                "lineno": d.get('lineno'),
                "snippet": d.get('value'),
                "rule": "example:ssl_session_cache_off",
                "context": d.get('context', [])
            })
    return issues
'''
        try:
            write_file(example_path, example_source)
        except Exception:
            pass

def load_module_by_name(name: str):
    """
    Load module from modules/<name>.py and return the module dict with run() function.
    """
    module_path = os.path.join(MODULES_DIR, f"{name}.py")
    if not os.path.exists(module_path):
        raise FileNotFoundError(f"Module not found: {module_path}")
    # Use runpy or importlib to import the module as a namespace
    import importlib.util, types
    spec = importlib.util.spec_from_file_location(f"ngmods.{name}", module_path)
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)  # type: ignore
    except Exception as e:
        raise RuntimeError(f"Failed to load module {name}: {e}")
    if not hasattr(mod, "run"):
        raise RuntimeError(f"Module {name} does not expose required function 'run(file_path, text, directives)'")
    return mod

# === Reporting: HTML/JSON/CSV ===

HTML_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>{title}</title>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<style>
:root {{
  --bg: #0f172a;
  --card: linear-gradient(180deg,#0b1220 0%, #07101a 100%);
  --text: #e6eef8;
  --muted: #9fb0c8;
  --code-bg: #05111a;
}}
html.light {{
  --bg: #f8fafc;
  --card: #ffffff;
  --text: #0f172a;
  --muted: #475569;
  --code-bg: #f1f5f9;
}}
body {{ font-family: Inter, Roboto, Arial, sans-serif; margin:20px; background:var(--bg); color:var(--text) }}
.header {{ display:flex; justify-content:space-between; align-items:center; margin-bottom:12px }}
.card {{ background:var(--card); border-radius:8px; padding:14px; margin-bottom:12px; box-shadow:0 6px 20px rgba(2,6,23,0.6) }}
.file-section {{ padding:12px; border-left:6px solid #e2e8f0; margin-bottom:12px }}
.issue {{ padding:12px; border-radius:8px; margin:10px 0; display:flex; gap:12px; align-items:flex-start; background: rgba(255,255,255,0.02) }}
.issue .meta {{ min-width:120px; font-weight:700 }}
.issue .desc {{ flex:1 }}
.small {{ font-size:12px; color:var(--muted) }}
.badge {{ display:inline-block; padding:6px 10px; border-radius:999px; font-weight:800; font-size:12px; color:white }}
.code {{ background:var(--code-bg); color:var(--text); padding:10px; border-radius:6px; font-family:monospace; font-size:13px; white-space:pre; overflow:auto }}
.meta-block {{ display:flex; gap:8px; flex-wrap:wrap; margin-top:8px }}
.kv {{ background: rgba(255,255,255,0.03); padding:6px 8px; border-radius:6px; font-size:13px }}
.footer {{ font-size:12px; color:var(--muted); margin-top:16px; text-align:center }}
.top-right {{ position:fixed; right:18px; top:18px; z-index:999 }}
.btn {{ background:rgba(255,255,255,0.04); color:var(--text); padding:8px 10px; border-radius:8px; cursor:pointer; border:none }}
</style>
</head>
<body class="dark">
<div class="top-right">
  <button id="toggleTheme" class="btn small">Toggle light/dark</button>
</div>
<div class="header">
  <div>
    <h1>{report_title}</h1>
    <div class="small">{timestamp}</div>
  </div>
  <div class="small">
    Scan target: {target} <br/> Files scanned: {count}
  </div>
</div>

<div class="card">
  <strong>Output directory:</strong> {outdir} <br/>
  <strong>Modules loaded:</strong> {modules_loaded}
</div>

{file_sections}

<div class="card">
  <h3>Discovered Virtual Hosts</h3>
  {vhost_summary}
</div>

<div class="footer">{footer}</div>

<script>
// Theme toggle
const toggle = document.getElementById('toggleTheme');
function setLight(light) {{
  if (light) document.documentElement.classList.add('light'), document.body.classList.remove('dark');
  else document.documentElement.classList.remove('light'), document.body.classList.add('dark');
  localStorage.setItem('nginx_conf_qs_light', light ? '1' : '0');
}}
toggle.onclick = () => {{
  const isLight = document.documentElement.classList.contains('light');
  setLight(!isLight);
}};
// Initialize from localStorage
(function() {{
  const v = localStorage.getItem('nginx_conf_qs_light');
  if (v === '1') setLight(true);
  else setLight(false);
}})();
</script>
</body>
</html>
"""

def render_issue_html(issue: Dict) -> str:
    color = SEVERITY_COLOR.get(issue.get('severity','INFO'), "#666")
    lineno = f"Line {issue['lineno']}" if issue.get('lineno') else ""
    snippet_html = ""
    if issue.get('snippet'):
        snippet_html = f'<div class="code">{html.escape(str(issue["snippet"]))}</div>'
    context_html = ""
    if issue.get('context'):
        context_html = '<div class="small" style="margin-top:6px;color:var(--muted)">Context: ' + html.escape(" / ".join(issue['context'])) + '</div>'
    return f'''
    <div class="issue" style="border-left:6px solid {color};">
      <div class="meta">
        <div class="badge" style="background:{color}">{html.escape(issue.get('severity',''))}</div>
        <div class="small">{html.escape(lineno)}</div>
      </div>
      <div class="desc">
        <div style="font-weight:800">{html.escape(issue.get('title',''))}</div>
        <div class="small">{html.escape(issue.get('description',''))}</div>
        {snippet_html}
        {context_html}
        <div class="small" style="margin-top:8px;color:var(--muted)">rule: {html.escape(issue.get('rule') or '-')}</div>
      </div>
    </div>
    '''

def render_file_section(path: str, data: Dict) -> str:
    counts = {"HIGH":0,"MEDIUM":0,"LOW":0,"INFO":0}
    for it in data.get('issues', []):
        counts[it['severity']] = counts.get(it['severity'], 0) + 1
    header_color = "#ff4d4d" if counts["HIGH"] else ("#ffae42" if counts["MEDIUM"] else ("#ffd24d" if counts["LOW"] else "#94d3a2"))
    header = f'<div class="card" style="border-left:6px solid {header_color}"><strong>{html.escape(path)}</strong><div class="small">Issues: {sum(counts.values())} — H:{counts["HIGH"]} M:{counts["MEDIUM"]} L:{counts["LOW"]} I:{counts["INFO"]}</div></div>'
    servers_html = ""
    if data.get('servers'):
        for s in data['servers']:
            sn = ", ".join(s.get('server_names') or []) or "(none)"
            locs = ", ".join(s.get('locations') or []) or "(none)"
            proxies = ", ".join(s.get('proxy_pass') or []) or "(none)"
            servers_html += f'<div class="kv"><strong>server_name:</strong> {html.escape(sn)} &nbsp; <strong>locations:</strong> {html.escape(locs)} &nbsp; <strong>proxy:</strong> {html.escape(proxies)}</div>'
    include_html = ""
    if data.get('includes'):
        include_html = '<div class="small" style="margin-top:6px"><strong>Includes:</strong> ' + html.escape(", ".join(data.get('includes'))) + '</div>'
    issues_html = ""
    for it in data.get('issues', []):
        snippet = None
        if it.get('lineno') and data.get('content'):
            lines = data['content'].splitlines()
            try:
                snippet = lines[it['lineno']-1].strip()
            except Exception:
                snippet = None
        it_copy = dict(it)
        it_copy['snippet'] = snippet
        issues_html += render_issue_html(it_copy)
    excerpt = "\n".join(data.get('content','').splitlines()[:30])
    excerpt_html = f'<div class="small" style="margin-top:8px"><strong>File excerpt (first 30 lines):</strong><div class="code">{html.escape(excerpt)}</div></div>'
    return header + '<div class="card">' + servers_html + include_html + issues_html + excerpt_html + '</div>'

def generate_reports(results: Dict[str, Dict], outdir: str, target: str, modules_loaded: List[str], min_severity: str):
    ts = utc_ts()
    outdir = os.path.abspath(outdir)
    ensure_dir(outdir)
    rawdir = os.path.join(outdir, "raw")
    ensure_dir(rawdir)
    # copy raw files
    for path, data in results.items():
        try:
            dest = os.path.join(rawdir, os.path.basename(path))
            write_file(dest, data.get('content',''))
        except Exception:
            pass
    # filter by severity
    filtered = {}
    for path, data in results.items():
        filtered_issues = [i for i in data.get('issues', []) if severity_filter_ok(i['severity'], min_severity)]
        filtered[path] = {
            "issues": filtered_issues,
            "servers": data.get('servers', []),
            "includes": data.get('includes', []),
            "content": data.get('content', '')
        }
    # JSON
    json_path = os.path.join(outdir, f"nginx-scan-{ts}.json")
    write_file(json_path, json.dumps(filtered, indent=2))
    # CSV
    csv_path = os.path.join(outdir, f"nginx-scan-{ts}.csv")
    rows=[]
    for path, data in filtered.items():
        for it in data.get('issues', []):
            rows.append({
                "file": path,
                "severity": it.get('severity'),
                "title": it.get('title'),
                "lineno": it.get('lineno') or "",
                "rule": it.get('rule') or "",
                "context": " / ".join(it.get('context') or [])
            })
    keys=["file","severity","title","lineno","rule","context"]
    try:
        with open(csv_path,"w",newline='',encoding="utf-8") as f:
            dw = csv.DictWriter(f, fieldnames=keys)
            dw.writeheader()
            for r in rows:
                dw.writerow(r)
    except Exception:
        pass
    # HTML
    html_filename = f"nginx-scan-{Path(target).name}-{ts}.html"
    html_path = os.path.join(outdir, html_filename)
    file_sections_html = ""
    vhosts = []
    for path, data in filtered.items():
        file_sections_html += render_file_section(path, data)
        for s in data.get('servers', []):
            vhosts.append({"file": path, "server_names": s.get('server_names', []), "locations": s.get('locations', []), "proxy": s.get('proxy_pass', [])})
    # build vhost summary table
    vhost_html = ""
    if vhosts:
        for v in vhosts:
            sn = ", ".join(v.get('server_names') or []) or "(none)"
            locs = ", ".join(v.get('locations') or []) or "(none)"
            proxies = ", ".join(v.get('proxy') or []) or "(none)"
            vhost_html += f'<div class="kv"><strong>file:</strong> {html.escape(v["file"])} &nbsp; <strong>server_name:</strong> {html.escape(sn)} &nbsp; <strong>locations:</strong> {html.escape(locs)} &nbsp; <strong>proxy:</strong> {html.escape(proxies)}</div>'
    else:
        vhost_html = '<div class="small">(no virtual hosts discovered)</div>'
    page = HTML_TEMPLATE.format(title=html.escape(TITLE_HTML),
                                report_title=html.escape(TITLE_HTML),
                                timestamp=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%SZ"),
                                target=html.escape(target),
                                count=len(filtered),
                                outdir=html.escape(outdir),
                                modules_loaded=html.escape(", ".join(modules_loaded) or "(none)"),
                                file_sections=file_sections_html,
                                vhost_summary=vhost_html,
                                footer=html.escape(FOOTER_ATTRIBUTION))
    write_file(html_path, page)
    return {"json": json_path, "csv": csv_path, "html": html_path, "rawdir": rawdir}

# === Main CLI ===

def parse_args():
    p = argparse.ArgumentParser(add_help=False)
    # custom help to include banner
    p.add_argument("-p","--path", required=True, help="Path to nginx config file or directory to scan")
    p.add_argument("-r","--results", default=DEFAULT_RESULTS_DIR, help="Directory to place results (default: reports/)")
    p.add_argument("-m","--module", action="append", help="Load additional module from modules/<name>.py (repeatable)", default=[])
    p.add_argument("-s","--min-severity", choices=["INFO","LOW","MEDIUM","HIGH"], default="INFO", help="Minimum severity to include in exports")
    p.add_argument("-v","--verbose", action="store_true", help="Verbose output")
    p.add_argument("-h","--help", action="store_true", help="Show help")
    return p.parse_args()

def print_help_and_exit():
    print(BANNER)
    print("Usage: ./nginx-conf-qs.py -p /path/to/nginx/conf -r reports -m example_module -v")
    print()
    print("Options:")
    print("  -p, --path           Path to nginx config file or directory to scan (required)")
    print("  -r, --results        Directory to place results (default: reports/)")
    print("  -m, --module         Load module from modules/<name>.py (repeatable). Example: -m example_module")
    print("  -s, --min-severity   Minimum severity to include in exports (INFO, LOW, MEDIUM, HIGH)")
    print("  -v, --verbose        Verbose output")
    print("  -h, --help           Show this help")
    print()
    print("Example modules directory layout (auto-created on first run):")
    print("  modules/example_module.py  # example module created for reference")
    print()
    sys.exit(0)

def main():
    args = parse_args()
    if args.help:
        print_help_and_exit()
    print(BANNER)
    target = args.path
    results_dir = args.results
    modules_to_load = args.module or []
    min_sev = args.min_severity
    verbose = args.verbose

    # prepare modules dir and example module
    ensure_modules_dir()

    # load modules
    loaded_modules = []
    module_objects = []
    for mn in modules_to_load:
        try:
            mod = load_module_by_name(mn)
            module_objects.append((mn, mod))
            loaded_modules.append(mn)
            if verbose:
                print("Loaded module:", mn)
        except Exception as e:
            print("Warning: failed to load module", mn, ":", e)

    # run scan
    if not os.path.exists(target):
        print("Error: target path does not exist:", target)
        sys.exit(2)
    results = full_scan(target, verbose=verbose)
    # apply plugin modules to each file result
    for path, data in list(results.items()):
        # load plugin results and append to issues
        file_text = data.get('content','')
        directives = data.get('directives', [])
        for (mn, mod) in module_objects:
            try:
                extra_issues = mod.run(path, file_text, directives)
                if extra_issues:
                    # normalize and append
                    for it in extra_issues:
                        # ensure minimal fields
                        if 'severity' not in it or 'title' not in it or 'description' not in it:
                            continue
                        data.setdefault('issues', []).append({
                            "severity": it.get('severity','INFO'),
                            "title": it.get('title'),
                            "description": it.get('description'),
                            "lineno": it.get('lineno'),
                            "snippet": it.get('snippet'),
                            "rule": it.get('rule'),
                            "context": it.get('context', [])
                        })
                if verbose:
                    print(f"Module {mn} ran on {path}, returned {len(extra_issues) if extra_issues else 0} issues")
            except Exception as e:
                print(f"Warning: module {mn} failed on {path}: {e}")

    # generate reports
    out = generate_reports(results, results_dir, target, loaded_modules, min_sev)
    print("Results written:")
    print(" - JSON:", out['json'])
    print(" - CSV: ", out['csv'])
    print(" - HTML: ", out['html'])
    print(" - Raw copied files in:", out['rawdir'])
    if verbose:
        total_issues = sum(len(d.get('issues',[])) for d in results.values())
        print(f"Scanned {len(results)} files — {total_issues} issues (min severity {min_sev})")

if __name__ == "__main__":
    main()
