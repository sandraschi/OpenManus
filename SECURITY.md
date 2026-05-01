# Security Policy

## Known Risks

OpenManus executes LLM-generated code and commands on your local machine.
This is inherently dangerous — the same capability that makes it powerful
makes it a vector for privilege escalation, data exfiltration, and system damage.

### Tool Risk Levels

| Tool | Risk | Mitigation |
|------|------|-----------|
| `bash` | **CRITICAL** — arbitrary shell commands as your user | Command denylist blocks rm -rf /, sudo, useradd, dd, mkfs, net user, fork bombs, cryptominers |
| `computer` | **HIGH** — full desktop keyboard/mouse/screenshot | User confirmation gate on keyboard input and screenshots (first use per session) |
| `python_execute` | **HIGH** — code execution on host | Restricted builtins; os/subprocess/socket imports blocked; eval/exec blocked; system path writes blocked |
| `browser_use` | **LOW** — runs in Playwright sandbox | Browser instance isolated by Chromium sandboxing |
| `str_replace_editor` | **MODERATE** — file read/write | Scoped to workspace directory |
| MCP server tools | **DEPENDS** — varies by connected server | Validate MCP server configs before connecting |

### Current Hardening (as of 2026-05)

1. **Bash command denylist** — regex patterns block destructive disk ops,
   privilege escalation, user management, sudo, fork bombs, and known malware downloads
2. **Python restricted builtins** — only safe builtins exposed; dangerous modules
   cannot be imported; eval/exec blocked; system-path file writes blocked
3. **Computer use confirmation gate** — keyboard input and screenshot actions
   require interactive terminal confirmation on first use per session
4. **API authentication** — optional `OPENMANUS_MCP_API_KEY` env var gates all
   REST API endpoints (except health/capabilities)

### What is NOT protected

- The bash denylist is regex-based and can be bypassed by a sufficiently clever
  attacker or compromised LLM (e.g., encoding, obfuscation, indirect execution)
- Python restricted builtins prevent `import os` but `builtins.__import__` tricks
  or ctypes-based escapes may still work
- The computer use confirmation gate is interactive only — if running headless,
  all actions proceed without confirmation
- API auth is optional — if `OPENMANUS_MCP_API_KEY` is not set, anyone who can
  reach the API port can call it

### Recommended Deployment Practices

1. **Never run as root/Administrator** — run as a limited user
2. **Use the Docker sandbox** — set `use_sandbox = true` in `config.toml`
3. **Set a strong API key** — `export OPENMANUS_MCP_API_KEY=$(openssl rand -hex 32)`
4. **Restrict network access** — bind API to `127.0.0.1` only (default)
5. **Review config.toml** — API keys stored in plaintext; consider using env vars
6. **Audit MCP server configs** — only connect to trusted MCP servers

## Reporting a Vulnerability

Do NOT file a public GitHub issue. Open a [security advisory](https://github.com/sandraschi/OpenManus/security/advisories)
or contact the maintainers directly.

## Related

- `app/tool/bash.py` — command denylist implementation
- `app/tool/python_execute.py` — restricted builtins
- `app/tool/local_computer_use.py` — confirmation gate
- `src/openmanus_mcp/api/app.py` — API authentication middleware
