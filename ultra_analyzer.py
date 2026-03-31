import asyncio
import json
import os
import re
import logging
from datetime import datetime
from colorama import Fore, init
from playwright.async_api import async_playwright

# Setup Professional Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='reports/audit.log'
)
init(autoreset=True)

class UltraAnalyzer:
    def __init__(self, use_tor=True, max_concurrency=3):
        self.report_dir = "reports"
        self.output_file = os.path.join(self.report_dir, "report.jsonl")
        self.max_concurrency = max_concurrency
        self.semaphore = asyncio.Semaphore(max_concurrency)
        # Playwright Tor Proxy format
        self.proxy_server = "socks5://127.0.0.1:9050" if use_tor else None
        
        os.makedirs(self.report_dir, exist_ok=True)
        
        with open('fingerprints.json', 'r') as f:
            self.fingerprints = json.load(f)

    async def analyze_with_browser(self, browser_context, url):
        """Renders JS and analyzes the DOM + Headers."""
        async with self.semaphore:
            result = {
                "url": url,
                "timestamp": datetime.now().isoformat(),
                "detections": [],
                "status": "unknown"
            }
            
            page = await browser_context.new_page()
            print(f"{Fore.CYAN}[*] Rendering JS for: {url}")
            
            try:
                # Intercept responses to check headers
                page.on("response", lambda res: self.check_headers(res, result))
                
                await page.goto(url, wait_until="networkidle", timeout=30000)
                content = await page.content()
                result["status"] = "online"

                # Run Body Fingerprints on fully rendered HTML
                for fp in self.fingerprints:
                    if fp["type"] == "body":
                        if re.search(fp["pattern"], content, re.I):
                            version = None
                            if fp.get("version"):
                                v_m = re.search(fp["version"], content)
                                version = v_m.group(1) if v_m else None
                            
                            if not any(d['plugin'] == fp['name'] for d in result["detections"]):
                                result["detections"].append({"plugin": fp["name"], "version": version})

            except Exception as e:
                logging.error(f"Browser Error {url}: {e}")
                result["status"] = "error"
            finally:
                await page.close()
                return result

    def check_headers(self, response, result):
        """Callback to analyze headers during page load."""
        for fp in self.fingerprints:
            if fp["type"] == "header":
                value = response.headers.get(fp["key"].lower(), "")
                if fp.get("pattern"):
                    m = re.search(fp["pattern"], value, re.I)
                    if m and not any(d['plugin'] == fp['name'] for d in result["detections"]):
                        version = m.group(1) if m.groups() else None
                        result["detections"].append({"plugin": fp["name"], "version": version})
                elif value and not any(d['plugin'] == fp['name'] for d in result["detections"]):
                    result["detections"].append({"plugin": fp["name"], "value": value})

    async def run(self, urls):
        print(f"{Fore.YELLOW}[!] Launching Headless Chromium Engine via Tor...")
        
        async with async_playwright() as p:
            # Launch browser with Tor Proxy
            browser = await p.chromium.launch(
                headless=True,
                proxy={"server": self.proxy_server} if self.proxy_server else None
            )
            context = await browser.new_context(ignore_https_errors=True)

            tasks = [self.analyze_with_browser(context, url) for url in urls]
            
            for task in asyncio.as_completed(tasks):
                analysis = await task
                
                # Atomic Save
                with open(self.output_file, "a") as f:
                    f.write(json.dumps(analysis) + "\n")
                
                if analysis["detections"]:
                    plugins = [d['plugin'] for d in analysis["detections"]]
                    print(f"{Fore.GREEN}[+] {analysis['url']}: {', '.join(plugins)}")
                else:
                    print(f"{Fore.WHITE}[-] {analysis['url']}: No matches")

            await browser.close()

if __name__ == "__main__":
    targets = ["https://wordpress.org", "https://reactjs.org"]
    
    # max_concurrency should be low (2-5) for browser-based tools 
    # because Chromium consumes significant RAM/CPU.
    scanner = UltraAnalyzer(use_tor=True, max_concurrency=2)
    asyncio.run(scanner.run(targets))