#!/usr/bin/env python3
import subprocess
import sys
import os
import json
import urllib.request
from datetime import datetime

def run_cmd(cmd, desc, hide_stderr=False):
    print(f"[*] {desc} ...")
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.stderr and result.stderr.strip():
            if hide_stderr:
                print(f"[!] {desc} encountered an internal issue; skipping detailed traceback.")
            else:
                print(f"[!] {desc} stderr:\n{result.stderr.strip()}")
        return result.stdout.strip()
    except Exception as e:
        print(f"[!] Error in {desc}: {e}")
        return ""

def check_web_basics(domain):
    info = {"headers": {}, "robots.txt": "Not found"}
    for scheme in ["https", "http"]:
        try:
            url = f"{scheme}://{domain}"
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                info["headers"] = dict(resp.headers)
            break
        except Exception:
            continue

    for scheme in ["https", "http"]:
        try:
            r_url = f"{scheme}://{domain}/robots.txt"
            req = urllib.request.Request(r_url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status == 200:
                    info["robots.txt"] = resp.read().decode("utf-8", errors="ignore")[:1500]
            break
        except Exception:
            continue
    return info

def generate_html(report, out_file):
    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Recon Report - {{report['target']}}</title>
    <style>
        body {{ font-family: Arial, sans-serif; background: #0f172a; color: #e2e8f0; margin: 20px; }}
        h1, h2 {{ color: #38bdf8; }}
        .card {{ background: #1e293b; padding: 15px; border-radius: 8px; margin-bottom: 20px; }}
        pre {{ background: #020617; padding: 10px; border-radius: 5px; overflow-x: auto; color: #a7f3d0; }}
        .badge {{ background: #0284c7; padding: 3px 8px; border-radius: 4px; font-size: 12px; }}
    </style>
</head>
<body>
    <h1>Automated Recon Report <span class="badge">{{report['target']}}</span></h1>
    <p>Generated on: {{report['timestamp']}}</p>

    <div class="card">
        <h2>1. Subdomains (Amass) [{{len(report['subdomains'])}}]</h2>
        <pre>{{chr(10).join(report['subdomains'])}}</pre>
    </div>

    <div class="card">
        <h2>2. Network & Port Scan (Nmap)</h2>
        <pre>{{report['nmap_scan'] or "No output"}}</pre>
    </div>

    <div class="card">
        <h2>3. Web Recon (Headers & robots.txt)</h2>
        <h3>HTTP Headers</h3>
        <pre>{{json.dumps(report['web_recon']['headers'], indent=2)}}</pre>
        <h3>robots.txt</h3>
        <pre>{{report['web_recon']['robots_txt']}}</pre>
    </div>

    <div class="card">
        <h2>4. Crawled Endpoints (Katana) [{{len(report['urls'])}}]</h2>
        <pre>{{chr(10).join(report['urls'])}}</pre>
    </div>

    <div class="card">
        <h2>5. Hidden Parameters (Arjun)</h2>
        <pre>{{json.dumps(report['arjun_params'], indent=2)}}</pre>
    </div>

    <div class="card">
        <h2>6. Vulnerability Findings (Nuclei) [{{len(report['nuclei_findings'])}}]</h2>
        <pre>{{chr(10).join(report['nuclei_findings']) if report['nuclei_findings'] else "No vulnerabilities detected"}}</pre>
    </div>
</body>
</html>'''
    with open(out_file, "w") as f:
        f.write(html)

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 recon_tool.py <authorized-domain>")
        sys.exit(1)

    domain = sys.argv[1].strip()
    out_dir = f"output_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    os.makedirs(out_dir, exist_ok=True)

    print(f"\n[*] Starting Integrated Recon on: {domain}")
    print(f"[+] Saving files to: {out_dir}\n")

    # 1. Subdomain Enumeration (Amass v5+)
    sub_file = f"{out_dir}/subdomains.txt"
    run_cmd(f"timeout 60 amass enum -d {domain}", "Running Amass Enum (max 60s)")
    subs_out = run_cmd(f"amass subs -names -d {domain}", "Extracting Amass Subdomains")
    subdomains = [line.strip() for line in subs_out.splitlines() if line.strip()]
    if domain not in subdomains:
        subdomains.insert(0, domain)
    with open(sub_file, "w") as f:
        f.write("\n".join(subdomains) + "\n")

    # 2. Network Recon (Nmap top ports & service detection)
    nmap_out = run_cmd(f"nmap -sV --top-ports 25 -T4 --host-timeout 20s {domain}", "Running Nmap (Port & Service Recon)")

    # 3. Web Recon (Headers & robots.txt)
    print("[*] Checking HTTP Headers & robots.txt ... ")
    web_info = check_web_basics(domain)

    # 4. Web Crawling (Katana)
    urls_file = f"{out_dir}/urls.txt"
    run_cmd(f"katana -list {sub_file} -jc -d 1 -c 20 -silent -o {urls_file}", "Running Katana (Web Crawling)")
    urls = []
    if os.path.exists(urls_file):
        with open(urls_file, "r") as f:
            urls = [line.strip() for line in f if line.strip()]

    # 5. Parameter Discovery (Arjun)
    param_urls_file = f"{out_dir}/param_urls.txt"
    arjun_out_file = f"{out_dir}/arjun.json"
    param_urls = [u for u in urls if '?' in u]
    arjun_data = {}
    if param_urls:
        with open(param_urls_file, "w") as f:
            f.write("\n".join(param_urls) + "\n")
        run_cmd(f"arjun -i {param_urls_file} -oJ {arjun_out_file}", "Running Arjun (Parameter Discovery)", hide_stderr=True)
        if os.path.exists(arjun_out_file):
            try:
                with open(arjun_out_file, "r") as f:
                    arjun_data = json.load(f)
            except Exception:
                arjun_data = {}
    else:
        print("[+] No parameterized URLs found, running Arjun on main domain ...")
        run_cmd(f"arjun -u https://{domain} -oJ {arjun_out_file}", "Running Arjun on main target", hide_stderr=True)
        if os.path.exists(arjun_out_file):
            try:
                with open(arjun_out_file, "r") as f:
                    arjun_data = json.load(f)
            except Exception:
                arjun_data = {}

    # 6. Vulnerability Scanning (Nuclei) - Fast scan on Katana URLs
    nuclei_file = f"{out_dir}/nuclei.jsonl"
    nuclei_findings = []
    if urls and os.path.exists(urls_file):
        run_cmd(f"nuclei -list {urls_file} -severity high,critical -rl 100 -c 15 -jsonl -o {nuclei_file}", "Running Nuclei on Katana URLs")
        if os.path.exists(nuclei_file):
            with open(nuclei_file, "r") as f:
                for line in f:
                    try:
                        data = json.loads(line)
                        template = data.get("template-id", "unknown")
                        info = data.get("info", {})
                        name = info.get("name", "")
                        severity = info.get("severity", "")
                        nuclei_findings.append(f"[{severity.upper()}] {template}: {name}")
                    except Exception:
                        pass
    else:
        print("[!] Skipping Nuclei: no crawled URLs found in urls.txt.")

    # Compile Final Report
    report = {
        "target": domain,
        "timestamp": datetime.now().isoformat(),
        "subdomains": subdomains,
        "nmap_scan": nmap_out,
        "web_recon": web_info,
        "urls": urls,
        "arjun_params": arjun_data,
        "nuclei_findings": nuclei_findings
    }

    json_report_path = f"{out_dir}/recon_report.json"
    html_report_path = f"{out_dir}/recon_report.html"

    with open(json_report_path, "w") as f:
        json.dump(report, f, indent=2)

    generate_html(report, html_report_path)

    print(f"\n[✓] Recon Complete!")
    print(f"Json Report : {json_report_path}")
    print(f"HTML Report : {html_report_path}\n")

if __name__ == '__main__':
    main()
