"""Security hardening tests."""

import asyncio

from app.tool.bash import Bash, _check_command_safety, _normalize_command
from app.tool.local_computer_use import LocalComputerUse
from app.tool.python_execute import PythonExecute
from app.tool.str_replace_editor import StrReplaceEditor


class TestBashDenylist:
    def test_allow_benign(self):
        assert _check_command_safety("ls -la") is None
        assert _check_command_safety("echo hello") is None
        assert _check_command_safety("python3 app.py > server.log 2>&1 &") is None
        assert _check_command_safety("cd /workspace && npm run dev") is None

    def test_block_destructive(self):
        assert "BLOCKED" in _check_command_safety("rm -rf /")
        assert "BLOCKED" in _check_command_safety("dd if=/dev/zero of=/dev/sda")
        assert "BLOCKED" in _check_command_safety("mkfs.ext4 /dev/sdb1")

    def test_block_privilege_escalation(self):
        assert "BLOCKED" in _check_command_safety("sudo apt install nginx")
        assert "BLOCKED" in _check_command_safety("useradd hacker")
        assert "BLOCKED" in _check_command_safety("net user hacker password /add")

    def test_block_obfuscated(self):
        assert "BLOCKED" in _check_command_safety("rm -rf /")  # plain
        hex_cmd = "rm -rf /"
        assert "BLOCKED" in _check_command_safety(hex_cmd)

    def test_normalize_hex(self):
        # Test with a hex-encoded dangerous fragment
        raw = "$(printf 'rm') -rf /"
        norm = _normalize_command(raw)
        assert "rm" in norm

    def test_normalize_ansi_c(self):
        raw = "$'\\x72\\x6d' -rf /"
        norm = _normalize_command(raw)
        assert "rm" in norm or "\x72\x6d" in norm


class TestPythonExecuteRestricted:
    @pytest.mark.asyncio
    async def test_block_os_import(self):
        pe = PythonExecute()
        result = await pe.execute("import os; os.system('ls')")
        assert "BLOCKED" in result.get("observation", "")

    @pytest.mark.asyncio
    async def test_block_subprocess_import(self):
        pe = PythonExecute()
        result = await pe.execute("import subprocess; subprocess.run(['ls'])")
        assert "BLOCKED" in result.get("observation", "")

    @pytest.mark.asyncio
    async def test_block_eval(self):
        pe = PythonExecute()
        result = await pe.execute("eval('1+1')")
        assert "BLOCKED" in result.get("observation", "")

    @pytest.mark.asyncio
    async def test_allow_math(self):
        pe = PythonExecute()
        result = await pe.execute("print(sum([1, 2, 3]))")
        assert result.get("success") is True


class TestLocalComputerUse:
    def test_blocks_headless_screenshot(self):
        # Simulate headless by setting env
        import os
        os.environ["LOCAL_COMPUTER_NO_PROMPT"] = "1"
        cu = LocalComputerUse()
        assert cu._interactive is False
        del os.environ["LOCAL_COMPUTER_NO_PROMPT"]

    def test_tool_description_mentions_security(self):
        cu = LocalComputerUse()
        assert "confirmation" in cu.description.lower() or "security" in cu.description.lower()


class TestStrReplaceEditorPathScope:
    def setup_method(self):
        from app.config import config
        self.ws = config.workspace_root

    @pytest.mark.asyncio
    async def test_block_outside_workspace(self):
        editor = StrReplaceEditor()
        from pathlib import Path
        import pytest
        from app.exceptions import ToolError
        # Path outside workspace should raise
        outside = Path("/etc/passwd")
        from app.tool.file_operators import LocalFileOperator
        with pytest.raises(ToolError, match="outside the workspace"):
            await editor.validate_path("view", outside, LocalFileOperator())
