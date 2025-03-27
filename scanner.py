#!/usr/bin/env python3
import aiohttp
import asyncio
import json
import re
import os
import hashlib
import logging
import argparse
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import ollama
from rich.console import Console
from rich.table import Table

# Configuration
AI_MODEL = "deepseek-coder:6.7b"
MAX_CONNECTIONS = 20  # Reduced for stability
MAX_AI_WORKERS = 5    # Fewer parallel AI calls
DEFAULT_OUTPUT_DIR = "scan_results"
os.makedirs(DEFAULT_OUTPUT_DIR, exist_ok=True)

console = Console()

# Critical vulnerability patterns
VULN_PATTERNS = {
    "RCE": {
        "patterns": [
            r"child_process\.exec\(",
            r"Function\(",
            r"vm\.runInThisContext\(",
            r"eval\(.*\.src\)"
        ],
        "severity": "critical",
        "bounty": "$1000-$5000"
    },
    "Auth_Bypass": {
        "patterns": [
            r"admin\s*=\s*true",
            r"bypass.*auth",
            r"jwt\.verify\(.*null\)",
            r"password\s*==\s*'.*'"
        ],
        "severity": "high",
        "bounty": "$500-$2000"
    },
    "XSS": {
        "patterns": [
            r"\.innerHTML\s*=",
            r"document\.write\(",
            r"\.setAttribute\(['\"]src['\"],"
        ],
        "severity": "medium",
        "bounty": "$200-$1000"
    }
}

class AIScanner:
    def __init__(self):
        self.should_exit = False
        self.ai_executor = ThreadPoolExecutor(max_workers=MAX_AI_WORKERS)
        
    async def analyze(self, code, context):
        """Safe AI analysis with timeout"""
        if self.should_exit:
            return None
            
        try:
            loop = asyncio.get_event_loop()
            response = await asyncio.wait_for(
                loop.run_in_executor(
                    self.ai_executor,
                    lambda: ollama.chat(
                        model=AI_MODEL,
                        messages=[{
                            'role': 'user',
                            'content': f"""Analyze this code for security vulnerabilities:
                            {context}
                            Code:
                            {code[:5000]}"""
                        }]
                    )
                ),
                timeout=30
            )
            
            if isinstance(response, dict):
                if 'message' in response and 'content' in response['message']:
                    return json.loads(response['message']['content'])
                return response.get('content', {})
            return {"error": "Unexpected response format"}
            
        except Exception as e:
            logging.error(f"AI analysis failed: {str(e)}")
            return None

class VulnerabilityScanner:
    def __init__(self):
        self.session = None
        self.ai_scanner = AIScanner()

    async def scan_file(self, file_path):
        """Complete scan pipeline for one file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Initial pattern matching
            findings = {}
            for vuln_type, data in VULN_PATTERNS.items():
                matches = []
                for pattern in data["patterns"]:
                    if re.search(pattern, content):
                        line_no = self._get_line_number(content, pattern)
                        matches.append({
                            "line": line_no,
                            "pattern": pattern,
                            "code": self._get_line(content, line_no)
                        })
                if matches:
                    findings[vuln_type] = {
                        "matches": matches,
                        "severity": data["severity"],
                        "bounty": data["bounty"]
                    }

            if not findings:
                return None

            # AI analysis for critical findings only
            ai_result = None
            if any(f["severity"] == "critical" for f in findings.values()):
                context = "Critical vulnerability found:\n" + "\n".join(
                    f"- {vuln_type} at line {m['line']}" 
                    for vuln_type, data in findings.items() 
                    for m in data["matches"]
                )
                ai_result = await self.ai_scanner.analyze(content, context)

            # Generate report
            report = {
                "file": file_path,
                "findings": findings,
                "ai_analysis": ai_result,
                "timestamp": datetime.now().isoformat()
            }

            # Save report
            filename = f"{hashlib.md5(file_path.encode()).hexdigest()}.json"
            with open(f"{DEFAULT_OUTPUT_DIR}/{filename}", 'w') as f:
                json.dump(report, f, indent=2)

            return report

        except Exception as e:
            logging.error(f"Error scanning {file_path}: {str(e)}")
            return None

    def _get_line_number(self, content, pattern):
        """Find line number of pattern match"""
        for i, line in enumerate(content.split('\n')):
            if re.search(pattern, line):
                return i + 1
        return 0

    def _get_line(self, content, line_no):
        """Get specific line from content"""
        lines = content.split('\n')
        if 0 < line_no <= len(lines):
            return lines[line_no-1].strip()
        return ""

    def print_results(self, results):
        """Display results in console"""
        table = Table(title="Scan Results", show_header=True)
        table.add_column("File")
        table.add_column("Vulnerability")
        table.add_column("Severity")
        table.add_column("Bounty")
        table.add_column("Line")

        for result in results:
            if not result:
                continue
                
            for vuln_type, data in result["findings"].items():
                severity_color = {
                    "critical": "red",
                    "high": "yellow",
                    "medium": "green"
                }.get(data["severity"], "white")
                
                for match in data["matches"]:
                    table.add_row(
                        os.path.basename(result["file"]),
                        vuln_type,
                        f"[{severity_color}]{data['severity']}",
                        data["bounty"],
                        str(match["line"])
                    )

        console.print(table)

async def main(file_path):
    """Main scanning workflow"""
    if not os.path.exists(file_path):
        console.print(f"[red]Error: File not found - {file_path}")
        return

    scanner = VulnerabilityScanner()
    result = await scanner.scan_file(file_path)
    
    if result:
        scanner.print_results([result])
        console.print(f"\n[green]Report saved to {DEFAULT_OUTPUT_DIR}/")
    else:
        console.print("[yellow]No vulnerabilities found!")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AI-Powered JavaScript Vulnerability Scanner")
    parser.add_argument("file", help="JavaScript file to scan")
    args = parser.parse_args()

    try:
        asyncio.run(main(args.file))
    except KeyboardInterrupt:
        console.print("\n[red]Scan interrupted by user!")
    except Exception as e:
        console.print(f"[red]Fatal error: {str(e)}")
