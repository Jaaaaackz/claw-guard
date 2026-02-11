# Claw Guard 🦞🛡️ - The Security Auditor for OpenClaw

**Claw Guard** is a specialized security auditing tool designed to keep your OpenClaw agent workspace safe. It scans the source code of AI skills for sensitive patterns, unauthorized environment access, and potential data exfiltration before you install them.

## Why Claw Guard?
OpenClaw skills are powerful because they have access to your environment. However, this power can be abused. Claw Guard acts as a "security gatekeeper," ensuring that a new skill doesn't:
- 🔴 Stealthily read your `USER.md`, `MEMORY.md`, or `.env` secrets.
- 🟡 Send your private data to unknown external servers via `POST` requests.
- 🔵 Execute suspicious shell commands or hidden background processes.

## Features
- **Regex-Based Pattern Matching**: Scans for hundreds of risky coding patterns.
- **Risk Categorization**:
    - **🔴 CRITICAL**: Direct privacy or credential theft attempts.
    - **🟡 WARNING**: Suspicious network or environment activity.
    - **🔵 INFO**: General observations (e.g., use of shell scripts).
- **Automated Recommendations**: Clear `PASS`, `REVIEW`, or `BLOCK` conclusions based on findings.
- **Detailed Audit Trail**: Identifies exact file names and line numbers of flagged code.

## Installation & Usage

1. **Clone the repository**:
   ```bash
   git clone https://github.com/Jaaaaackz/claw-guard.git
   cd claw-guard
   ```

2. **Run an audit**:
   ```bash
   python3 audit.py <path_to_skill_directory>
   ```

3. **Check out the examples**:
   - Audit a malicious skill: `python3 audit.py examples/bad_skill`
   - Audit a safe skill: `python3 audit.py examples/good_skill`

## Roadmap
- [ ] Integration as a standard OpenClaw Skill.
- [ ] High-performance TypeScript/Node.js implementation.
- [ ] Integration with `openclaw install` CLI flow.
- [ ] Support for AI-powered semantic risk analysis.

## Contributing
We welcome contributions from the OpenClaw community! If you find a new "red flag" pattern, please open an Issue or a Pull Request.

---
*Created by Jack Zzz & his AI Assistant (XiaoMishu_OC) with love for the OpenClaw community.* 🦞🛡️
