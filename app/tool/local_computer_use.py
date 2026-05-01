"""Windows-native computer use tool using win32 API directly.

Provides mouse, keyboard, and screenshot control without requiring
a Daytona sandbox. Replaces ComputerUseTool for local Windows usage.
"""

import asyncio
import base64
import io
import os
import sys
import time
from typing import Dict, Literal, Optional

from pydantic import Field

from app.tool.base import BaseTool, ToolResult

try:
    import win32api
    import win32con
    import win32gui
    import win32ui
    HAS_WIN32 = True
except ImportError:
    HAS_WIN32 = False


KEYBOARD_KEYS = [
    "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m",
    "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z",
    "0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
    "enter", "esc", "backspace", "tab", "space", "delete",
    "ctrl", "alt", "shift", "win",
    "up", "down", "left", "right",
    "f1", "f2", "f3", "f4", "f5", "f6", "f7", "f8", "f9", "f10", "f11", "f12",
    "ctrl+c", "ctrl+v", "ctrl+x", "ctrl+z", "ctrl+a", "ctrl+s",
    "alt+tab", "alt+f4", "ctrl+alt+delete",
]

MOUSE_BUTTONS = ["left", "right", "middle"]

_VK_MAP = {
    "enter": win32con.VK_RETURN, "esc": win32con.VK_ESCAPE,
    "backspace": win32con.VK_BACK, "tab": win32con.VK_TAB,
    "space": win32con.VK_SPACE, "delete": win32con.VK_DELETE,
    "ctrl": win32con.VK_CONTROL, "alt": win32con.VK_MENU,
    "shift": win32con.VK_SHIFT, "win": win32con.VK_LWIN,
    "up": win32con.VK_UP, "down": win32con.VK_DOWN,
    "left": win32con.VK_LEFT, "right": win32con.VK_RIGHT,
    "f1": win32con.VK_F1, "f2": win32con.VK_F2, "f3": win32con.VK_F3,
    "f4": win32con.VK_F4, "f5": win32con.VK_F5, "f6": win32con.VK_F6,
    "f7": win32con.VK_F7, "f8": win32con.VK_F8, "f9": win32con.VK_F9,
    "f10": win32con.VK_F10, "f11": win32con.VK_F11, "f12": win32con.VK_F12,
}

_LOCAL_CU_DESCRIPTION = """\
Windows-native computer automation tool for controlling the local desktop.

Provides mouse, keyboard, and screenshot control directly via win32 API.
No external sandbox or container required — operates on the native Windows desktop.

Key capabilities:
* Mouse Control: Move, click (left/right/middle), drag, scroll
* Keyboard Input: Type text, press keys, hotkey combinations
* Screenshots: Capture full screen or specific regions
* Waiting: Pause execution for specified duration

Use this when you need to automate desktop applications, fill forms,
interact with native Windows UI, or perform GUI-based operations.
"""


class LocalComputerUse(BaseTool):
    """Windows-native computer automation using win32 API directly."""

    name: str = "computer"
    description: str = _LOCAL_CU_DESCRIPTION
    parameters: dict = {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": [
                    "move", "click", "double_click", "right_click",
                    "scroll", "type", "press", "hotkey",
                    "screenshot", "wait", "drag",
                ],
                "description": "The computer action to perform",
            },
            "x": {"type": "integer", "description": "X coordinate for mouse actions"},
            "y": {"type": "integer", "description": "Y coordinate for mouse actions"},
            "button": {
                "type": "string", "enum": MOUSE_BUTTONS, "default": "left",
            },
            "text": {"type": "string", "description": "Text to type"},
            "key": {
                "type": "string", "enum": KEYBOARD_KEYS,
                "description": "Key to press",
            },
            "keys": {
                "type": "string",
                "description": "Key combination for hotkey (e.g. 'ctrl+s')",
            },
            "clicks": {
                "type": "integer", "description": "Number of clicks", "default": 1,
            },
            "amount": {
                "type": "integer",
                "description": "Scroll amount (positive=up, negative=down)",
            },
            "duration": {
                "type": "number",
                "description": "Duration in seconds to wait", "default": 0.5,
            },
        },
        "required": ["action"],
    }

    _mouse_x: int = 0
    _mouse_y: int = 0
    _confirmed: bool = False

    async def _require_confirmation(self, action: str, detail: str = "") -> bool:
        """Prompt user for confirmation of sensitive actions."""
        if self._confirmed:
            return True
        print(f"\n⚠️  SECURITY: {action} requested")
        if detail:
            print(f"   Detail: {detail}")
        print(f"   Allow this action? (y/N): ", end="", flush=True)
        try:
            loop = asyncio.get_event_loop()
            resp = await loop.run_in_executor(None, lambda: sys.stdin.readline().strip().lower())
            if resp == "y":
                self._confirmed = True
                return True
            return False
        except Exception:
            return False

    async def execute(
        self,
        action: Literal[
            "move", "click", "double_click", "right_click",
            "scroll", "type", "press", "hotkey",
            "screenshot", "wait", "drag",
        ],
        x: Optional[int] = None,
        y: Optional[int] = None,
        button: str = "left",
        text: Optional[str] = None,
        key: Optional[str] = None,
        keys: Optional[str] = None,
        clicks: int = 1,
        amount: Optional[int] = None,
        duration: float = 0.5,
        **kwargs,
    ) -> ToolResult:
        if not HAS_WIN32:
            return ToolResult(error="win32api not available on this platform")

        try:
            # Confirmation gates for sensitive operations
            if action in ("type", "press", "hotkey") and not self._confirmed:
                detail = f"action={action}"
                if action == "type" and text:
                    detail = f"text='{text[:50]}...' " if len(text or "") > 50 else f"text='{text}'"
                if action == "hotkey" and keys:
                    detail = f"keys={keys}"
                ok = await self._require_confirmation(f"Keyboard input: {action}", detail)
                if not ok:
                    return ToolResult(output="BLOCKED: keyboard action requires user confirmation")

            if action == "screenshot" and not self._confirmed:
                ok = await self._require_confirmation("Screen capture", "Full desktop screenshot")
                if not ok:
                    return ToolResult(output="BLOCKED: screenshot requires user confirmation")

            if action == "move":
                return await self._move(x, y)
            elif action == "click":
                return await self._click(x, y, button, clicks)
            elif action == "double_click":
                return await self._click(x, y, button, 2)
            elif action == "right_click":
                return await self._click(x, y, "right", 1)
            elif action == "scroll":
                return await self._scroll(amount)
            elif action == "type":
                return await self._type(text)
            elif action == "press":
                return await self._press(key)
            elif action == "hotkey":
                return await self._hotkey(keys)
            elif action == "screenshot":
                return await self._screenshot()
            elif action == "wait":
                await asyncio.sleep(duration)
                return ToolResult(output=f"Waited {duration}s")
            elif action == "drag":
                return await self._drag(x, y)
            else:
                return ToolResult(error=f"Unknown action: {action}")
        except Exception as e:
            return ToolResult(error=f"Computer action failed: {e}")

    async def _move(self, x: Optional[int], y: Optional[int]) -> ToolResult:
        if x is None or y is None:
            return ToolResult(error="x and y required")
        win32api.SetCursorPos((x, y))
        self._mouse_x, self._mouse_y = x, y
        return ToolResult(output=f"Moved to ({x}, {y})")

    async def _click(
        self, x: Optional[int], y: Optional[int],
        button: str, num_clicks: int,
    ) -> ToolResult:
        cx = x if x is not None else self._mouse_x
        cy = y if y is not None else self._mouse_y
        b = win32con.MOUSEEVENTF_LEFTDOWN if button == "left" else (
            win32con.MOUSEEVENTF_RIGHTDOWN if button == "right" else win32con.MOUSEEVENTF_MIDDLEDOWN
        )
        b_up = win32con.MOUSEEVENTF_LEFTUP if button == "left" else (
            win32con.MOUSEEVENTF_RIGHTUP if button == "right" else win32con.MOUSEEVENTF_MIDDLEUP
        )
        win32api.SetCursorPos((cx, cy))
        for _ in range(num_clicks):
            win32api.mouse_event(b, cx, cy, 0, 0)
            win32api.mouse_event(b_up, cx, cy, 0, 0)
            time.sleep(0.05)
        self._mouse_x, self._mouse_y = cx, cy
        return ToolResult(output=f"{num_clicks}x {button} click at ({cx}, {cy})")

    async def _scroll(self, amount: Optional[int]) -> ToolResult:
        if amount is None:
            return ToolResult(error="amount required")
        win32api.mouse_event(win32con.MOUSEEVENTF_WHEEL, 0, 0, amount * 120, 0)
        return ToolResult(output=f"Scrolled by {amount}")

    async def _type(self, text: Optional[str]) -> ToolResult:
        if not text:
            return ToolResult(error="text required")
        for ch in text:
            win32api.keybd_event(ord(ch.upper()), 0, 0, 0)
            win32api.keybd_event(ord(ch.upper()), 0, win32con.KEYEVENTF_KEYUP, 0)
            time.sleep(0.01)
        return ToolResult(output=f"Typed: {text[:50]}{'...' if len(text) > 50 else ''}")

    async def _press(self, key: Optional[str]) -> ToolResult:
        if not key:
            return ToolResult(error="key required")
        vk = _VK_MAP.get(key.lower())
        if vk is None:
            if len(key) == 1:
                vk = ord(key.upper())
            else:
                return ToolResult(error=f"Unknown key: {key}")
        win32api.keybd_event(vk, 0, 0, 0)
        win32api.keybd_event(vk, 0, win32con.KEYEVENTF_KEYUP, 0)
        return ToolResult(output=f"Pressed: {key}")

    async def _hotkey(self, keys: Optional[str]) -> ToolResult:
        if not keys:
            return ToolResult(error="keys required")
        parts = keys.lower().split("+")
        vks = []
        for p in parts:
            vk = _VK_MAP.get(p.strip())
            if vk is None and len(p) == 1:
                vk = ord(p.upper())
            if vk:
                vks.append(vk)
        for vk in vks:
            win32api.keybd_event(vk, 0, 0, 0)
            time.sleep(0.02)
        for vk in reversed(vks):
            win32api.keybd_event(vk, 0, win32con.KEYEVENTF_KEYUP, 0)
            time.sleep(0.02)
        return ToolResult(output=f"Hotkey: {keys}")

    async def _screenshot(self) -> ToolResult:
        hwnd = win32gui.GetDesktopWindow()
        dc = win32gui.GetWindowDC(hwnd)
        try:
            dc_obj = win32ui.CreateDCFromHandle(dc)
            w = win32api.GetSystemMetrics(win32con.SM_CXSCREEN)
            h = win32api.GetSystemMetrics(win32con.SM_CYSCREEN)
            bmp = win32ui.CreateBitmap()
            bmp.CreateCompatibleBitmap(dc_obj, w, h)
            mem_dc = dc_obj.CreateCompatibleDC()
            mem_dc.SelectObject(bmp)
            mem_dc.BitBlt((0, 0), (w, h), dc_obj, (0, 0), win32con.SRCCOPY)

            bmp_info = bmp.GetInfo()
            bmp_str = bmp.GetBitmapBits(True)
            img = Image.frombuffer(
                "RGB", (bmp_info["bmWidth"], bmp_info["bmHeight"]),
                bmp_str, "raw", "BGRX", 0, 1,
            )
            buf = io.BytesIO()
            img.save(buf, format="PNG")
            b64 = base64.b64encode(buf.getvalue()).decode()

            os.makedirs("screenshots", exist_ok=True)
            ts = time.strftime("%Y%m%d_%H%M%S")
            path = f"screenshots/screenshot_{ts}.png"
            img.save(path)

            mem_dc.DeleteDC()
            win32gui.DeleteObject(bmp.GetHandle())
            return ToolResult(
                output=f"Screenshot saved to {path}",
                base64_image=b64,
            )
        finally:
            win32gui.ReleaseDC(hwnd, dc)

    async def _drag(self, x: Optional[int], y: Optional[int]) -> ToolResult:
        if x is None or y is None:
            return ToolResult(error="x and y required")
        sx, sy = self._mouse_x, self._mouse_y
        win32api.mouse_event(win32con.MOUSEEVENTF_LEFTDOWN, sx, sy, 0, 0)
        time.sleep(0.05)
        steps = 10
        for i in range(1, steps + 1):
            ix = sx + (x - sx) * i // steps
            iy = sy + (y - sy) * i // steps
            win32api.SetCursorPos((ix, iy))
            time.sleep(0.01)
        win32api.mouse_event(win32con.MOUSEEVENTF_LEFTUP, x, y, 0, 0)
        self._mouse_x, self._mouse_y = x, y
        return ToolResult(output=f"Dragged from ({sx}, {sy}) to ({x}, {y})")
