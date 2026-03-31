import asyncio
import json
import os
import re
import logging
import sys
from datetime import datetime
from colorama import Fore, init
from playwright.async_api import async_playwright

# --- INITIALIZATION ---
# 1. Create the directory BEFORE logging starts to avoid the FileNotFoundError
REPORT_DIR = "reports"
if not os.path.exists(REPORT_DIR):
    os.makedirs(REPORT_DIR)

# 2. Setup Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename=os.path.join(REPORT_DIR, 'audit.log')
)
init(autoreset=True)

class UltraAnalyzer:
    def __init__(self, use_tor=True, max_concurrency=3):
        self.report_dir = REPORT_DIR
        self.output_file = os.path.join(self.report_dir, "report.jsonl")
        self.max_concurrency = max_concurrency
        self.semaphore = asyncio.Semaphore(max_concurrency)
        
        # SOCKS5h ensures DNS is resolved by the proxy (Tor), preventing DNS leaks.
        self.proxy_server = "socks5://127.0.0.1:9050" if use_tor else None
        
        # Load Fingerprints with error handling
        try:
            with open('fingerprints.json', 'r') as f:
                self.fingerprints = json.load(f)
        except FileNotFoundError:
            print(f"{Fore.RED}[!] Critical: fingerprints.json not found.")
            sys.exit(1)

    async def analyze_with_browser(self, browser_context, url):
        """Bounded worker that manages a single browser page."""
        async with self.semaphore:
            result = {
                "url": url,
                "timestamp": datetime.now().isoformat(),
                "detections": [],
                "status": "unknown"
            }
            
            page = await browser_context.new_page()
            # Set a realistic User-Agent to avoid basic bot detection
            await page.set_extra_http_headers({
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
            })

            print(f"{Fore.CYAN}[*] Analyzing: {url}")
            
            try:
                # Attach header listener
                page.on("response", lambda res: self.check_headers(res, result))
                
                # Navigate and wait for network to settle
                await page.goto(url, wait_until="networkidle", timeout=45000)
                
                # Get fully rendered HTML
                content = await page.content()
                result["status"] = "online"

                # Run Body Fingerprints
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
        """Header analysis callback logic."""
        for fp in self.fingerprints:
            if fp.get("type") == "header":
                # Ensure key is lowercased for comparison
                header_val = response.headers.get(fp["key"].lower(), "")
                if not header_val:
                    continue

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
                        result["detections"].append({
                            "plugin": fp["name"], 
                            "version": version,
                            "value": header_val if not version else None
                        })

    async def run(self, urls):
        """Main orchestrator for the Playwright session."""
        if not urls:
            print(f"{Fore.RED}[!] No targets provided.")
            return

        print(f"{Fore.YELLOW}[!] Engine Active. Concurrency: {self.max_concurrency} | Proxy: {self.proxy_server}")
        
        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                proxy={"server": self.proxy_server} if self.proxy_server else None
            )
            # Create a shared context for all pages
            context = await browser.new_context(ignore_https_errors=True)

            tasks = [self.analyze_with_browser(context, url) for url in urls]
            
            for task in asyncio.as_completed(tasks):
                analysis = await task
                
                # Append result to JSONL immediately
                with open(self.output_file, "a") as f:
                    f.write(json.dumps(analysis) + "\n")
                
                # Console Output
                if analysis.get("detections"):
                    found = [d['plugin'] for d in analysis["detections"]]
                    print(f"{Fore.GREEN}[+] {analysis['url']} -> {', '.join(found)}")
                else:
                    print(f"{Fore.WHITE}[-] {analysis['url']} -> No detections")

            await browser.close()

if __name__ == "__main__":
    # Example Target List
    TARGET_LIST = [
        "https://wordpress.org",
        "https://reactjs.org",
        "https://nginx.org"
    ]
    
    # Setup Analyzer
    # Note: max_concurrency > 5 can be heavy on RAM when using Browsers.
    scanner = UltraAnalyzer(use_tor=True, max_concurrency=3)
    
    try:
        asyncio.run(scanner.run(TARGET_LIST))
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Scan interrupted by user.")
    finally:
        print(f"{Fore.YELLOW}[***] Audit complete. Results: {os.path.abspath(REPORT_DIR)}")