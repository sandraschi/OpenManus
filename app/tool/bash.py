import asyncio
import os
import re
from typing import Optional

from app.exceptions import ToolError
from app.tool.base import BaseTool, CLIResult

_BASH_DESCRIPTION = """Execute a bash command in the terminal.
* Long running commands: For commands that may run indefinitely, it should be run in the background and the output should be redirected to a file, e.g. command = `python3 app.py > server.log 2>&1 &`.
* Interactive: If a bash command returns exit code `-1`, this means the process is not yet finished. The assistant must then send a second call to terminal with an empty `command` (which will retrieve any additional logs), or it can send additional text (set `command` to the text) to STDIN of the running process, or it can send command=`ctrl+c` to interrupt the process.
* Timeout: If a command execution result says "Command timed out. Sending SIGINT to the process", the assistant should retry running the command in the background.
"""

DENY_PATTERNS = [
    # Destructive disk operations
    r"^\s*rm\s+-rf\s+/\s*$",
    r"^\s*rm\s+-rf\s+/boot",
    r"^\s*rm\s+-rf\s+/etc",
    r"^\s*rm\s+-rf\s+/usr",
    r"^\s*rm\s+-rf\s+/var",
    r"^\s*dd\s+if=/dev/",
    r"^\s*dd\s+of=/dev/",
    r"^\s*mkfs\.",
    r"^\s*mkswap",
    r"^\s*fdisk\s+/dev/",
    r"^\s*parted\s+/dev/",
    r"^\s*format\s+[a-z]:",
    # Privilege escalation
    r"^\s*net\s+user\s+\S+\s+\S+\s+/add",
    r"^\s*net\s+localgroup\s+administrators?\s+\S+\s+/add",
    r"^\s*usermod\s+-aG\s+(sudo|wheel|admin)",
    r"^\s*useradd\s+",
    r"^\s*passwd\s+",
    r"^\s*chmod\s+4777",
    r"^\s*chmod\s+777\s+/",
    r"^\s*sudo\s+",
    # Network exfiltration / tunneling
    r"^\s*nc\s+-[a-z]*e\s+",
    r"^\s*bash\s+-[ic]\s+",
    r"^\s*sh\s+-[ic]\s+",
    # Fork bomb / DoS
    r":\(\)\s*\{",
    r"^\s*while\s+true\s*;.*do\s+.*done",
    # Cryptominers / malware download
    r"curl.*(?:miner|xmrig|cryptonight)",
    r"wget.*(?:miner|xmrig|cryptonight)",
    # Registry / system config (Windows)
    r"^\s*reg\s+(delete|add)\s+HK",
]

DENY_WARNINGS = {
    "rm": "Recursive destructive deletion is blocked",
    "dd": "Raw disk write operations are blocked",
    "mkfs": "Filesystem creation is blocked",
    "net user": "User account management is blocked",
    "sudo": "Privilege escalation via sudo is blocked",
    "chmod 4777": "SUID bit setting is blocked",
}


_OBFUSCATION_PATTERNS = [
    r"\\x[0-9a-fA-F]{2}",       # hex escape \x2d
    r"\\[0-7]{3}",               # octal escape \0155
    r"\$\(printf[^)]+\)",       # $(printf ...)
    r"\$\(echo[^)]+\)",         # $(echo ...)
    r"\$\(xxd[^)]+\)",          # $(xxd ...)
    r"`printf[^`]+`",           # `printf ...`
    r"`echo[^`]+`",             # `echo ...`
    r'base64\s+-d',             # base64 decode
    r"python\s+-c\s+['\"].*\\x",  # python -c with hex
    r"perl\s+-e\s+['\"].*\\x",    # perl -e with hex
    r"\$'[^']*\\x",              # $'...\x...' ANSI-C quoting
    r"\$\{[^}]+\}",              # variable expansion ${...}
]

_DANGEROUS_KEYWORDS = [
    "rm", "dd", "mkfs", "mkswap", "fdisk", "parted", "format",
    "sudo", "su", "chmod", "chown", "useradd", "usermod", "passwd",
    "net user", "net localgroup",
    "nc -e", "bash -i", "sh -i",
    ":(){", "while true",
    "xmrig", "miner", "cryptonight",
    "wget", "curl.*-O", "curl.*-o",
    "reg delete", "reg add",
    "> /dev/", "< /dev/",
]


def _normalize_command(cmd: str) -> str:
    """Strip common shell obfuscation to reveal dangerous intent."""
    normal = cmd

    # Remove ANSI-C quoting wrapper: $'...'
    normal = re.sub(r"\$'(.*?)'", lambda m: m.group(1), normal)

    # Decode hex escapes \x2d -> -
    try:
        normal = re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), normal)
    except Exception:
        pass

    # Decode octal escapes \0155 -> m
    try:
        normal = re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), normal)
    except Exception:
        pass

    # Resolve statically evaluable printf: $(printf '%s' 'rm') -> rm
    normal = re.sub(
        r'\$\(printf\s+([^)]+)\)',
        lambda m: re.sub(r"'[^']*'\s*", "", m.group(1)).strip().strip("'\""),
        normal,
    )

    # Resolve echo: $(echo 'rm') -> rm
    normal = re.sub(
        r'\$\(echo\s+([^)]+)\)',
        lambda m: m.group(1).strip().strip("'\""),
        normal,
    )

    # Remove backticks with simple commands
    normal = re.sub(r'`([^`]+)`', lambda m: m.group(1).strip().strip("'\""), normal)

    return normal


def _has_obfuscation(cmd: str) -> bool:
    """Check if command uses obfuscation techniques."""
    return any(re.search(p, cmd) for p in _OBFUSCATION_PATTERNS)


def _has_dangerous_keyword(cmd: str) -> bool:
    """Check if command contains dangerous keywords."""
    cmd_lower = cmd.lower()
    return any(kw.lower() in cmd_lower for kw in _DANGEROUS_KEYWORDS)


def _check_command_safety(command: str) -> str | None:
    if not command or not command.strip():
        return None

    cmd = command.strip()

    # Check raw command against patterns
    for pattern in DENY_PATTERNS:
        if re.search(pattern, cmd, re.IGNORECASE):
            for key, warning in DENY_WARNINGS.items():
                if key.lower() in cmd.lower():
                    return f"BLOCKED by security policy: {warning}"
            return "BLOCKED by security policy: command matches a denied pattern"

    # If no obfuscation, we're done
    if not _has_obfuscation(cmd):
        return None

    # Normalize and re-check for bypass attempts
    normal = _normalize_command(cmd)

    for pattern in DENY_PATTERNS:
        if re.search(pattern, normal, re.IGNORECASE):
            return "BLOCKED by security policy: obfuscated dangerous command detected"

    # If obfuscation + dangerous keywords = likely attack
    if _has_dangerous_keyword(cmd) or _has_dangerous_keyword(normal):
        return "BLOCKED by security policy: obfuscation with dangerous keywords detected"

    return None


class _BashSession:
    """A session of a bash shell."""

    _started: bool
    _process: asyncio.subprocess.Process

    command: str = "/bin/bash"
    _output_delay: float = 0.2
    _timeout: float = 120.0
    _sentinel: str = "<<exit>>"

    def __init__(self):
        self._started = False
        self._timed_out = False

    async def start(self):
        if self._started:
            return

        self._process = await asyncio.create_subprocess_shell(
            self.command,
            preexec_fn=os.setsid,
            shell=True,
            bufsize=0,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        self._started = True

    def stop(self):
        if not self._started:
            raise ToolError("Session has not started.")
        if self._process.returncode is not None:
            return
        self._process.terminate()

    async def run(self, command: str):
        if not self._started:
            raise ToolError("Session has not started.")
        if self._process.returncode is not None:
            return CLIResult(
                system="tool must be restarted",
                error=f"bash has exited with returncode {self._process.returncode}",
            )
        if self._timed_out:
            raise ToolError(
                f"timed out: bash has not returned in {self._timeout} seconds and must be restarted",
            )

        assert self._process.stdin
        assert self._process.stdout
        assert self._process.stderr

        command_blocked = _check_command_safety(command)
        if command_blocked:
            return CLIResult(error=command_blocked, output="")

        self._process.stdin.write(
            command.encode() + f"; echo '{self._sentinel}'\n".encode()
        )
        await self._process.stdin.drain()

        try:
            async with asyncio.timeout(self._timeout):
                while True:
                    await asyncio.sleep(self._output_delay)
                    output = self._process.stdout._buffer.decode()
                    if self._sentinel in output:
                        output = output[: output.index(self._sentinel)]
                        break
        except asyncio.TimeoutError:
            self._timed_out = True
            raise ToolError(
                f"timed out: bash has not returned in {self._timeout} seconds and must be restarted",
            ) from None

        if output.endswith("\n"):
            output = output[:-1]

        error = self._process.stderr._buffer.decode()
        if error.endswith("\n"):
            error = error[:-1]

        self._process.stdout._buffer.clear()
        self._process.stderr._buffer.clear()

        return CLIResult(output=output, error=error)


class Bash(BaseTool):
    """A tool for executing bash commands with security filtering."""

    name: str = "bash"
    description: str = _BASH_DESCRIPTION
    parameters: dict = {
        "type": "object",
        "properties": {
            "command": {
                "type": "string",
                "description": "The bash command to execute. Can be empty to view additional logs when previous exit code is `-1`. Can be `ctrl+c` to interrupt the currently running process.",
            },
        },
        "required": ["command"],
    }

    _session: Optional[_BashSession] = None
    _warned: bool = False

    async def execute(
        self, command: str | None = None, restart: bool = False, **kwargs
    ) -> CLIResult:
        if not self._warned:
            self._warned = True

        if restart:
            if self._session:
                self._session.stop()
            self._session = _BashSession()
            await self._session.start()
            return CLIResult(system="tool has been restarted.")

        if self._session is None:
            self._session = _BashSession()
            await self._session.start()

        if command is not None:
            return await self._session.run(command)

        raise ToolError("no command provided.")
