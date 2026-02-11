# Claw Guard 🦞🛡️

**Claw Guard** is a security auditing tool for OpenClaw skills. It scans skill source code for sensitive patterns before installation to prevent user data exfiltration and unauthorized environment access.

## Features
- 🔴 **High Risk Detection**: Flags attempts to read `USER.md`, `MEMORY.md`, `.env`, SSH keys, or API tokens.
- 🟡 **Medium Risk Detection**: Flags environment variable access and suspicious network activity (e.g., `POST` requests, webhooks).
- 🔵 **Low Risk Detection**: Flags shell execution and subprocess spawns.
- **Automated Gatekeeping**: Provides clear "Install" or "Block" recommendations.

## Usage
```bash
python3 audit.py <path_to_skill_directory>
```

## Contributing
Inspired by the OpenClaw community. Feel free to open issues or PRs to add more detection patterns!
