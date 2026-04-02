import asyncio
import json
import os
import re
import logging
import sys
import argparse  # Added for dynamic CLI input
from datetime import datetime
from colorama import Fore, init
from playwright.async_api import async_playwright

# --- INITIALIZATION ---
REPORT_DIR = "reports"
if not os.path.exists(REPORT_DIR):
    os.makedirs(REPORT_DIR)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename=os.path.join(REPORT_DIR, 'audit.log')
)
init(autoreset=True)

class UltraAnalyzer:
    def __init__(self, use_tor=True, max_concurrency=3):
        self.report_dir = REPORT_DIR
        self.output_file = os.path.join(self.report_dir, "report.json")
        self.max_concurrency = max_concurrency
        self.semaphore = asyncio.Semaphore(max_concurrency)
        self.proxy_server = "socks5://127.0.0.1:9050" if use_tor else None
        
        try:
            with open('fingerprints.json', 'r') as f:
                self.fingerprints = json.load(f)
        except FileNotFoundError:
            print(f"{Fore.RED}[!] Critical: fingerprints.json not found.")
            sys.exit(1)

    async def analyze_with_browser(self, browser_context, url):
        async with self.semaphore:
            # Basic URL cleaning
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url

            result = {"url": url, "timestamp": datetime.now().isoformat(), "detections": [], "status": "unknown"}
            page = await browser_context.new_page()
            await page.set_extra_http_headers({
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
            })

            print(f"{Fore.CYAN}[*] Analyzing: {url}")
            
            try:
                page.on("response", lambda res: self.check_headers(res, result))
                await page.goto(url, wait_until="networkidle", timeout=45000)
                content = await page.content()
                result["status"] = "online"

                for fp in self.fingerprints:
                    if fp.get("type") == "body":
                        if re.search(fp["pattern"], content, re.I):
                            version = None
                            if fp.get("version"):
                                v_m = re.search(fp["version"], content)
                                version = v_m.group(1) if v_m else None
                            if not any(d['plugin'] == fp['name'] for d in result["detections"]):
                                result["detections"].append({"plugin": fp["name"], "version": version})
            except Exception as e:
                logging.error(f"Scan failed for {url}: {str(e)}")
                result["status"] = f"error: {type(e).__name__}"
            finally:
                await page.close()
                return result

    def check_headers(self, response, result):
        for fp in self.fingerprints:
            if fp.get("type") == "header":
                header_val = response.headers.get(fp["key"].lower(), "")
                if not header_val: continue
                match_found = False
                version = None
                if fp.get("pattern"):
                    m = re.search(fp["pattern"], header_val, re.I)
                    if m:
                        match_found = True
                        version = m.group(1) if m.groups() else None
                else:
                    match_found = True

                if match_found:
                    if not any(d['plugin'] == fp['name'] for d in result["detections"]):
                        result["detections"].append({"plugin": fp["name"], "version": version, "value": header_val if not version else None})

    async def run(self, urls):
        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                proxy={"server": self.proxy_server} if self.proxy_server else None
            )
            context = await browser.new_context(ignore_https_errors=True)
            tasks = [self.analyze_with_browser(context, url) for url in urls]
            
            for task in asyncio.as_completed(tasks):
                analysis = await task
                with open(self.output_file, "a") as f:
                    f.write(json.dumps(analysis) + "\n")
                
                if analysis.get("detections"):
                    found = [d['plugin'] for d in analysis["detections"]]
                    print(f"{Fore.GREEN}[+] {analysis['url']} -> {', '.join(found)}")
                else:
                    print(f"{Fore.WHITE}[-] {analysis['url']} -> No detections")
            await browser.close()

def parse_args():
    parser = argparse.ArgumentParser(description="UltraAnalyzer - Pro Fingerprinter")
    parser.add_argument("target", nargs="*", help="URL(s) or path to a text file containing URLs")
    parser.add_argument("--no-tor", action="store_true", help="Disable Tor proxy")
    parser.add_argument("--threads", type=int, default=3, help="Max concurrent browser instances")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    targets = []

    for item in args.target:
        if os.path.isfile(item):
            with open(item, 'r') as f:
                targets.extend([line.strip() for line in f if line.strip()])
        else:
            targets.append(item)

    if not targets:
        print(f"{Fore.RED}[!] Error: No targets provided. Usage: python3 ultra_analyzer.py <url> or <file.txt>")
        sys.exit(1)

    scanner = UltraAnalyzer(use_tor=not args.no_tor, max_concurrency=args.threads)
    
    try:
        asyncio.run(scanner.run(targets))
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Terminated by user.")