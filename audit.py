#!/usr/bin/env python3
import os
import sys
import re
from pathlib import Path

# Risk levels and their patterns
SENSITIVE_PATTERNS = {
    "CRITICAL (高危 - 隐私泄露)": {
        "level": "🔴 HIGH",
        "patterns": [
            r"USER\.md", r"MEMORY\.md", r"memory/", r"\.env", r"openclaw\.json", 
            r"id_rsa", r"id_ed25519", r"\.ssh", r"credentials", r"api_key", r"password"
        ]
    },
    "WARNING (中危 - 环境访问/外部通信)": {
        "level": "🟡 MEDIUM",
        "patterns": [
            r"process\.env", r"os\.environ", r"os\.getenv", r"getenv", 
            r"axios\.post", r"requests\.post", r"webhook", r"socket"
        ]
    },
    "INFO (低危 - 脚本执行)": {
        "level": "🔵 LOW",
        "patterns": [
            r"subprocess", r"sh ", r"bash ", r"system\(", r"exec\(", r"eval\("
        ]
    }
}

def scan_file(file_path):
    findings = []
    try:
        content = file_path.read_text(errors='ignore')
        for category, info in SENSITIVE_PATTERNS.items():
            for pattern in info["patterns"]:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    findings.append({
                        "category": category,
                        "level": info["level"],
                        "pattern": pattern,
                        "count": len(matches)
                    })
    except Exception as e:
        findings.append({"category": "Error", "level": "UNKNOWN", "pattern": str(e), "count": 0})
    return findings

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 skill_scanner.py <path_to_skill_directory>")
        sys.exit(1)

    skill_path = Path(sys.argv[1])
    if not skill_path.is_dir():
        print(f"Error: {skill_path} is not a directory.")
        sys.exit(1)

    print(f"\n🛡️  Skills 安全审计报告: {skill_path.name}")
    print("=" * 60)
    
    risk_summary = {"🔴 HIGH": 0, "🟡 MEDIUM": 0, "🔵 LOW": 0}
    file_count = 0
    
    for root, dirs, files in os.walk(skill_path):
        if ".git" in root: continue
        for file in files:
            file_count += 1
            file_path = Path(root) / file
            findings = scan_file(file_path)
            if findings:
                rel_path = file_path.relative_to(skill_path)
                print(f"\n📂 文件: {rel_path}")
                for f in findings:
                    print(f"  [{f['level']}] {f['category']}: 发现 '{f['pattern']}' ({f['count']} 次)")
                    risk_summary[f['level']] += 1

    print("\n" + "=" * 60)
    print(f"📊 审计汇总 ({file_count} 个文件):")
    print(f"  - 高危 (🔴): {risk_summary['🔴 HIGH']}")
    print(f"  - 中危 (🟡): {risk_summary['🟡 MEDIUM']}")
    print(f"  - 低危 (🔵): {risk_summary['🔵 LOW']}")
    
    if risk_summary['🔴 HIGH'] > 0:
        print("\n❌ 结论: 发现高危隐私访问风险！在未手动确认前，禁止执行安装。")
        sys.exit(1)
    elif risk_summary['🟡 MEDIUM'] > 0:
        print("\n⚠️ 结论: 存在敏感操作，请核对网络/环境调用是否必要。")
    else:
        print("\n✅ 结论: 扫描通过，未发现明显的隐私风险点。")

if __name__ == "__main__":
    main()
