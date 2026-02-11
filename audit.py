#!/usr/bin/env python3
"""
Claw Guard 🦞🛡️ v3 - Intelligent Security Auditor for OpenClaw.
Features: Comment awareness, Risk categorization, and User-controlled installation.
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
        "patterns": {
            r"(?<!['\"])(USER\.md|MEMORY\.md|memory/|id_rsa|id_ed25519|\.ssh)": "Unauthorized access to sensitive user files/keys.",
            r"\.env|openclaw\.json": "Attempting to access global secrets or configuration.",
            r"credentials|api_key|password|token": "Sensitive credential keywords found.",
            r"eval\(|exec\(": "Highly dangerous dynamic code execution."
        }
    },
    RISK_LEVELS["WARNING"]: {
        "patterns": {
            r"process\.env|os\.environ|os\.getenv": "Reading environment variables.",
            r"axios\.post|requests\.post|urllib\.request\.urlopen": "Outbound data transmission detected.",
            r"webhook|socket|https?://(?!github\.com|openclaw\.ai)": "Communication with non-standard domains.",
            r"subprocess|spawn|system\(": "Shell command execution."
        }
    }
}

def is_comment(line):
    """Simple check to skip common comment patterns."""
    l = line.strip()
    return l.startswith('#') or l.startswith('//') or l.startswith('*') or l.startswith('/*')

def scan_file(file_path):
    findings = []
    try:
        content = file_path.read_text(errors='ignore')
        lines = content.splitlines()
        for i, line in enumerate(lines):
            # Skip if it's a comment to reduce false positives
            if is_comment(line):
                continue
                
            for risk_name, config in SENSITIVE_PATTERNS.items():
                for pattern, reason in config["patterns"].items():
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
    parser.add_argument("--force", "-f", action="store_true", help="Non-interactive mode (for CI/CD)")
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
                    print(f"    └─ Line {f['line_no']}: Found '{f['pattern']}' -> {f['line_content']}")
                    if f['level'] in total_findings:
                        total_findings[f['level']] += 1

    print("\n" + "=" * 80)
    print(f"📊 Audit Summary ({file_count} files scanned):")
    for level, count in total_findings.items():
        if count > 0:
            print(f"  {level}: {count}")
    
    # Decisions
    has_critical = total_findings[RISK_LEVELS["CRITICAL"]] > 0
    has_warning = total_findings[RISK_LEVELS["WARNING"]] > 0

    if has_critical:
        print("\n❌ [ACTION REQUIRED] Critical risks detected!")
        if args.force:
            print("Force mode enabled, but blocking due to critical risk.")
            sys.exit(1)
        else:
            choice = input("\nDo you want to PROCEED with the installation despite these risks? (y/N): ").strip().lower()
            if choice == 'y':
                print("\n✅ User authorized. Proceeding to installation...")
                sys.exit(0)
            else:
                print("\n🛑 Installation blocked by user.")
                sys.exit(1)
    elif has_warning:
        print("\n⚠️  [NOTICE] Medium risks detected. Please review manually.")
        sys.exit(0)
    else:
        print("\n✅ PASS: No significant security risks found.")
        sys.exit(0)

if __name__ == "__main__":
    main()
