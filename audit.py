#!/usr/bin/env python3
"""
Claw Guard 🦞🛡️ - Skill Security Auditor for OpenClaw.
A tool to scan OpenClaw skills for potentially malicious code patterns.
"""
import os
import sys
import re
import argparse
from pathlib import Path

# --- Configuration ---
RISK_LEVELS = {
    "CRITICAL": "🔴 CRITICAL",
    "WARNING": "🟡 WARNING ",
    "INFO": "🔵 INFO    "
}

SENSITIVE_PATTERNS = {
    RISK_LEVELS["CRITICAL"]: {
        "description": "High risk of user privacy or credential theft.",
        "patterns": {
            r"USER\.md|MEMORY\.md|memory/": "Access to long-term memory or user profile.",
            r"\.env|openclaw\.json": "Access to global configuration or secrets.",
            r"id_rsa|id_ed25519|\.ssh": "Access to private SSH keys.",
            r"credentials|api_key|password|token": "Detection of sensitive credential-related keywords.",
            r"eval\(|exec\(": "Dynamic code execution (highly dangerous)."
        }
    },
    RISK_LEVELS["WARNING"]: {
        "description": "Environment access or suspicious network communication.",
        "patterns": {
            r"os\.environ|os\.getenv|process\.env": "Reading environment variables.",
            r"axios\.post|requests\.post|urllib\.request\.urlopen": "Outbound data transmission.",
            r"webhook|socket|https?://(?!github\.com|openclaw\.ai)": "Communication with non-standard domains.",
            r"subprocess|spawn|system\(": "Shell command execution."
        }
    },
    RISK_LEVELS["INFO"]: {
        "description": "General system observations.",
        "patterns": {
            r"\.sh|\.bash": "Inclusion of shell scripts.",
            r"chmod|chown": "File permission modifications."
        }
    }
}

def scan_file(file_path):
    findings = []
    try:
        content = file_path.read_text(errors='ignore')
        lines = content.splitlines()
        for risk_name, config in SENSITIVE_PATTERNS.items():
            for pattern, reason in config["patterns"].items():
                for i, line in enumerate(lines):
                    if re.search(pattern, line, re.IGNORECASE):
                        findings.append({
                            "level": risk_name,
                            "pattern": pattern,
                            "reason": reason,
                            "line_no": i + 1,
                            "line_content": line.strip()[:80]
                        })
    except Exception as e:
        findings.append({"level": "ERROR", "pattern": "FILE_READ", "reason": str(e), "line_no": 0, "line_content": ""})
    return findings

def main():
    parser = argparse.ArgumentParser(description="Claw Guard - Audit OpenClaw skills for security.")
    parser.add_argument("path", help="Path to the skill directory to audit")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show detailed line contents")
    args = parser.parse_args()

    skill_path = Path(args.path)
    if not skill_path.is_dir():
        print(f"Error: {skill_path} is not a directory.")
        sys.exit(1)

    print(f"\n🛡️  Claw Guard: Auditing '{skill_path.name}'")
    print("=" * 80)
    
    total_findings = {l: 0 for l in RISK_LEVELS.values()}
    file_count = 0
    
    for root, dirs, files in os.walk(skill_path):
        if ".git" in root or "node_modules" in root: continue
        for file in files:
            file_count += 1
            file_path = Path(root) / file
            findings = scan_file(file_path)
            if findings:
                rel_path = file_path.relative_to(skill_path)
                print(f"\n📂 File: {rel_path}")
                for f in findings:
                    print(f"  [{f['level']}] {f['reason']}")
                    print(f"    └─ Line {f['line_no']}: Found '{f['pattern']}'")
                    if args.verbose:
                        print(f"    └─ Code: {f['line_content']}")
                    if f['level'] in total_findings:
                        total_findings[f['level']] += 1

    print("\n" + "=" * 80)
    print(f"📊 Audit Summary ({file_count} files scanned):")
    for level, count in total_findings.items():
        print(f"  {level}: {count}")
    
    print("\n💡 Recommendation:")
    if total_findings[RISK_LEVELS["CRITICAL"]] > 0:
        print("  ❌ BLOCK: Critical risks detected. Do not install without thorough code review.")
        sys.exit(1)
    elif total_findings[RISK_LEVELS["WARNING"]] > 0:
        print("  ⚠️ REVIEW: Medium risks detected. Verify if environment/network access is justified.")
    else:
        print("  ✅ PASS: No significant security risks found.")

if __name__ == "__main__":
    main()
