import multiprocessing
import sys
from io import StringIO
from typing import Dict

from app.tool.base import BaseTool

_BLOCKED_MODULES = [
    "os", "subprocess", "shutil", "socket",
    "ctypes", "signal", "multiprocessing",
    "threading", "asyncio", "importlib",
    "pickle", "shelve", "dbm",
]

_SAFE_BUILTINS = {
    "abs": abs, "all": all, "any": any, "ascii": ascii,
    "bin": bin, "bool": bool, "bytearray": bytearray,
    "bytes": bytes, "callable": callable, "chr": chr,
    "complex": complex, "dict": dict, "dir": dir,
    "divmod": divmod, "enumerate": enumerate, "filter": filter,
    "float": float, "format": format, "frozenset": frozenset,
    "getattr": getattr, "hasattr": hasattr, "hash": hash,
    "hex": hex, "id": id, "int": int, "isinstance": isinstance,
    "issubclass": issubclass, "iter": iter, "len": len,
    "list": list, "locals": locals, "map": map, "max": max,
    "min": min, "next": next, "object": object, "oct": oct,
    "ord": ord, "pow": pow, "print": print, "range": range,
    "repr": repr, "reversed": reversed, "round": round,
    "set": set, "slice": slice, "sorted": sorted,
    "str": str, "sum": sum, "super": super, "tuple": tuple,
    "type": type, "vars": vars, "zip": zip,
    "True": True, "False": False, "None": None,
    "Exception": Exception, "ValueError": ValueError,
    "TypeError": TypeError, "KeyError": KeyError,
    "IndexError": IndexError, "AttributeError": AttributeError,
    "ImportError": ImportError, "StopIteration": StopIteration,
    "RuntimeError": RuntimeError, "ZeroDivisionError": ZeroDivisionError,
    "ArithmeticError": ArithmeticError, "MemoryError": MemoryError,
    "NameError": NameError, "SyntaxError": SyntaxError,
    "BaseException": BaseException, "_NoneType": type(None),
}

_SAFE_GLOBALS = {"__builtins__": _SAFE_BUILTINS}


class PythonExecute(BaseTool):
    """A tool for executing Python code with timeout and safety restrictions.

    Security: dangerous modules (os, subprocess, shutil, socket, etc.) are
    blocked. Only safe builtins and basic types are available.
    """

    name: str = "python_execute"
    description: str = (
        "Executes Python code string with restricted sandbox. "
        "Only print outputs are visible. "
        "Dangerous modules (os, subprocess, shutil, socket) are blocked. "
        "Use print statements to see results."
    )
    parameters: dict = {
        "type": "object",
        "properties": {
            "code": {
                "type": "string",
                "description": "The Python code to execute.",
            },
        },
        "required": ["code"],
    }

    def _check_code(self, code: str) -> str | None:
        for mod in _BLOCKED_MODULES:
            if f"import {mod}" in code or f"from {mod}" in code:
                return f"BLOCKED: importing '{mod}' is not allowed for security reasons"
        if "eval(" in code or "exec(" in code:
            return "BLOCKED: eval() and exec() are not allowed for security reasons"
        if "__import__" in code:
            return "BLOCKED: __import__ is not allowed for security reasons"
        if "open(" in code and any(p in code for p in ["'/", '"/', "'root", '"root', "'etc", '"etc']):
            return "BLOCKED: file operations on system paths are not allowed"
        return None

    def _run_code(self, code: str, result_dict: dict) -> None:
        original_stdout = sys.stdout
        try:
            blocked = self._check_code(code)
            if blocked:
                result_dict["observation"] = blocked
                result_dict["success"] = False
                return

            output_buffer = StringIO()
            sys.stdout = output_buffer
            exec(code, _SAFE_GLOBALS.copy(), _SAFE_GLOBALS.copy())
            result_dict["observation"] = output_buffer.getvalue()
            result_dict["success"] = True
        except Exception as e:
            result_dict["observation"] = str(e)
            result_dict["success"] = False
        finally:
            sys.stdout = original_stdout

    async def execute(
        self,
        code: str,
        timeout: int = 5,
    ) -> Dict:
        """
        Executes the provided Python code with a timeout.

        Args:
            code (str): The Python code to execute.
            timeout (int): Execution timeout in seconds.

        Returns:
            Dict containing execution result and observation.
        """
        result_dict: Dict = {"observation": "", "success": False}

        process = multiprocessing.Process(
            target=self._run_code, args=(code, result_dict)
        )
        process.start()
        process.join(timeout)

        if process.is_alive():
            process.terminate()
            process.join(1)
            result_dict["observation"] = f"Execution timed out after {timeout}s"
            result_dict["success"] = False

        return result_dict
