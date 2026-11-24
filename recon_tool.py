#!/usr/bin/env python3
import argparse
import datetime
import html
import json
import os
import shutil
import subprocess
import urllib.error
import urllib.request


def tool_exists(name: str) -> bool:
    return shutil.which(name) is not None


def run_cmd(cmd: list[str], timeout: int = 300) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except subprocess.TimeoutExpired:
        return 124, "", f"Command timed out after {timeout}s: {' '.join(cmd)}"
    except Exception as exc:
        return 1, "", str(exc)


def run_amass(target: str) -> list[str]:
    print("[*] Extracting Amass Subdomains ...")
    if not tool_exists("amass"):
        print("[-] Amass not found in PATH. Skipping.")
        return []

    code, out, err = run_cmd(["amass", "enum", "-passive", "-d", target], timeout=240)
    if err:
        print(f"[!] Amass stderr: {err.splitlines()[0]}")
    if code != 0 and not out:
        return []

    return sorted({line.strip() for line in out.splitlines() if line.strip()})


def run_nmap(target: str) -> str:
    print("[*] Running Nmap (Port & Service Recon) ...")
    if not tool_exists("nmap"):
        print("[-] Nmap not found in PATH. Skipping.")
        return "Nmap not installed"

    code, out, err = run_cmd(["nmap", "-F", "-sV", "--open", target], timeout=240)
    if err:
        print(f"[!] Nmap stderr: {err.splitlines()[0]}")
    return out if out else (err or "No open ports/output")


def run_web_recon(target: str) -> dict:
    print("[*] Checking HTTP Headers & robots.txt ...")
    base_url = target if target.startswith(("http://", "https://")) else f"https://{target}"
    headers_data = {}
    robots_content = ""

    for candidate in (base_url, base_url.replace("https://", "http://", 1)):
        try:
            req = urllib.request.Request(
                candidate,
                headers={"User-Agent": "Mozilla/5.0 (ReconFramework)"},
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                headers_data = {
                    "url": resp.geturl(),
                    "status": resp.status,
                    "headers": dict(resp.headers.items()),
                }
                base_url = resp.geturl().rstrip("/")
                break
        except Exception as exc:
            headers_data = {"attempted_url": candidate, "error": str(exc)}

    robots_url = f"{base_url}/robots.txt"
    try:
        req = urllib.request.Request(
            robots_url,
            headers={"User-Agent": "Mozilla/5.0 (ReconFramework)"},
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            robots_content = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        robots_content = f"HTTP {exc.code} fetching {robots_url}"
    except Exception as exc:
        robots_content = f"Error fetching {robots_url}: {exc}"

    return {
        "headers": headers_data,
        "robots_txt": robots_content,
    }


def run_katana(target: str) -> list[str]:
    print("[*] Running Katana (Web Crawling) ...")
    if not tool_exists("katana"):
        print("[-] Katana not found in PATH. Skipping.")
        return []

    url = target if target.startswith(("http://", "https://")) else f"https://{target}"
    code, out, err = run_cmd(["katana", "-u", url, "-silent"], timeout=240)
    if err:
        print(f"[!] Katana stderr: {err.splitlines()[0]}")
    if code != 0 and not out:
        return []

    return sorted({line.strip() for line in out.splitlines() if line.strip()})


def run_arjun(target: str, urls: list[str]) -> dict:
    print("[*] Running Arjun on main target ...")
    if not tool_exists("arjun"):
        print("[-] Arjun not found in PATH. Skipping.")
        return {}

    url = target if target.startswith(("http://", "https://")) else f"https://{target}"
    for candidate in urls:
        if "?" in candidate or "=" in candidate:
            url = candidate
            break

    code, out, err = run_cmd(["arjun", "-u", url], timeout=180)
    if err:
        print(f"[!] Arjun stderr: {err.splitlines()[0]}")

    try:
        return json.loads(out) if out else {}
    except json.JSONDecodeError:
        return {"target_url": url, "raw_output": out}


def run_nuclei(target: str, urls: list[str], out_dir: str) -> list[str]:
    print("[*] Running Nuclei on Katana URLs ...")
    if not tool_exists("nuclei"):
        print("[-] Nuclei not found in PATH. Skipping.")
        return []

    targets_file = os.path.join(out_dir, "nuclei_targets.txt")
    base_url = target if target.startswith(("http://", "https://")) else f"https://{target}"
    unique_targets = [base_url] + [u for u in urls if u.startswith(("http://", "https://"))]
    unique_targets = list(dict.fromkeys(unique_targets))

    with open(targets_file, "w", encoding="utf-8") as f:
        for item in unique_targets:
            f.write(item + "\n")

    code, out, err = run_cmd(
        ["nuclei", "-l", targets_file, "-silent"],
        timeout=300,
    )
    if err:
        print(f"[!] Nuclei stderr: {err.splitlines()[0]}")
    if code != 0 and not out:
        return []

    return [line.strip() for line in out.splitlines() if line.strip()]


def save_html_report(report: dict, output_path: str) -> str:
    target = html.escape(str(report.get("target", "")))
    timestamp = html.escape(str(report.get("timestamp", "")))

    subdomains = report.get("subdomains") or []
    subdomains_html = (
        html.escape("\n".join(subdomains)) if subdomains else "No subdomains found"
    )

    nmap_scan = report.get("nmap_scan")
    nmap_html = html.escape(str(nmap_scan)) if nmap_scan else "No output"

    web_recon = report.get("web_recon") or {}
    headers_data = web_recon.get("headers") or {}
    headers_html = html.escape(json.dumps(headers_data, indent=2))

    robots_txt = web_recon.get("robots_txt")
    robots_html = html.escape(str(robots_txt)) if robots_txt else "No robots.txt found"

    urls = report.get("urls") or []
    urls_html = html.escape("\n".join(urls)) if urls else "No endpoints crawled"

    arjun_params = report.get("arjun_params") or {}
    arjun_html = html.escape(json.dumps(arjun_params, indent=2))

    nuclei_findings = report.get("nuclei_findings") or []
    nuclei_html = (
        html.escape("\n".join(nuclei_findings))
        if nuclei_findings
        else "No vulnerabilities detected"
    )

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Recon Report - {target}</title>
  <style>
    body {{
      font-family: Arial, sans-serif;
      background-color: #0f172a;
      color: #e2e8f0;
      margin: 0;
      padding: 24px;
    }}
    h1 {{
      margin-bottom: 6px;
      color: #38bdf8;
    }}
    .meta {{
      color: #94a3b8;
      margin-bottom: 24px;
    }}
    .section {{
      background-color: #1e293b;
      border: 1px solid #334155;
      border-radius: 8px;
      padding: 16px;
      margin-bottom: 18px;
    }}
    .section h2 {{
      margin-top: 0;
      font-size: 18px;
      color: #f8fafc;
    }}
    .section h3 {{
      font-size: 15px;
      color: #cbd5e1;
      margin-bottom: 8px;
    }}
    pre {{
      background-color: #0b1120;
      color: #e2e8f0;
      padding: 12px;
      border-radius: 6px;
      overflow-x: auto;
      white-space: pre-wrap;
      word-break: break-word;
      margin: 0;
    }}
  </style>
</head>
<body>
  <h1>Automated Recon Report ({target})</h1>
  <div class="meta">Generated on: {timestamp}</div>

  <div class="section">
    <h2>1. Subdomains (Amass) [{len(subdomains)}]</h2>
    <pre>{subdomains_html}</pre>
  </div>

  <div class="section">
    <h2>2. Network &amp; Port Scan (Nmap)</h2>
    <pre>{nmap_html}</pre>
  </div>

  <div class="section">
    <h2>3. Web Recon (Headers &amp; robots.txt)</h2>
    <h3>HTTP Headers</h3>
    <pre>{headers_html}</pre>
    <h3>robots.txt</h3>
    <pre>{robots_html}</pre>
  </div>

  <div class="section">
    <h2>4. Crawled Endpoints (Katana) [{len(urls)}]</h2>
    <pre>{urls_html}</pre>
  </div>

  <div class="section">
    <h2>5. Hidden Parameters (Arjun)</h2>
    <pre>{arjun_html}</pre>
  </div>

  <div class="section">
    <h2>6. Vulnerability Findings (Nuclei) [{len(nuclei_findings)}]</h2>
    <pre>{nuclei_html}</pre>
  </div>
</body>
</html>
"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    return output_path


def main() -> None:
    parser = argparse.ArgumentParser(description="Automated Recon Framework")
    parser.add_argument("-t", "--target", required=True, help="Target domain or URL")
    args = parser.parse_args()

    clean_target = args.target.replace("https://", "").replace("http://", "").strip("/")
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = f"output_{clean_target}_{stamp}"
    os.makedirs(out_dir, exist_ok=True)

    subdomains = run_amass(clean_target)
    nmap_scan = run_nmap(clean_target)
    web_recon = run_web_recon(clean_target)
    urls = run_katana(clean_target)
    arjun_params = run_arjun(clean_target, urls)
    nuclei_findings = run_nuclei(clean_target, urls, out_dir)

    report = {
        "target": clean_target,
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "subdomains": subdomains,
        "nmap_scan": nmap_scan,
        "web_recon": web_recon,
        "urls": urls,
        "arjun_params": arjun_params,
        "nuclei_findings": nuclei_findings,
    }

    json_path = os.path.join(out_dir, "recon_report.json")
    html_path = os.path.join(out_dir, "recon_report.html")

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    save_html_report(report, html_path)

    print("\n[v] Recon Complete!")
    print(f"Json Report : {json_path}")
    print(f"HTML Report : {html_path}")


if __name__ == "__main__":
    main()
