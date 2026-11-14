"""Guard: the GUI must be importable on every platform CI runs.

The 86-test suite does not import openhail.gui, so a broken gui.py would pass
CI green and only fail for a user. This test is the cheap tripwire that makes
that impossible.

Named after the failure it prevents, per standing rule.
"""

from __future__ import annotations

import ast
import importlib
import io
import pathlib


GUI_PATH = pathlib.Path(__file__).resolve().parent.parent / "src" / "openhail" / "gui.py"


def test_gui_module_file_exists():
    assert GUI_PATH.is_file(), "src/openhail/gui.py is missing"


def test_gui_module_parses():
    ast.parse(io.open(GUI_PATH, encoding="utf-8").read())


def test_gui_module_imports_without_a_display():
    """Importing must not construct Tk or touch the network.

    tkinter is imported at module scope, which is fine - it is stdlib and
    available everywhere Python is packaged with Tk. What would break CI is
    constructing a Tk root at import time, which needs a live display.
    """
    mod = importlib.import_module("openhail.gui")
    assert hasattr(mod, "RpcClient")
    assert hasattr(mod, "RpcError")
    assert hasattr(mod, "App")
    assert callable(mod.main)


def test_gui_imports_only_stdlib():
    """No third-party GUI dependency may creep in.

    Every extra dependency is supply-chain risk on a machine that holds mail
    credentials, so the import list is pinned by test rather than by intention.
    """
    allowed = {
        "__future__",
        "json",
        "queue",
        "subprocess",
        "sys",
        "threading",
        "tkinter",
        "pathlib",
        "typing",
        "validate",  # relative sibling inside the package
    }
    tree = ast.parse(io.open(GUI_PATH, encoding="utf-8").read())
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                found.add(node.module.split(".")[0] if node.module else "")
            elif node.module:
                found.add(node.module.split(".")[0])
    unexpected = found - allowed - {""}
    assert not unexpected, f"unexpected third-party imports in gui.py: {sorted(unexpected)}"


def test_gui_entry_point_declared_in_pyproject():
    """The console script must stay registered, or `openhail-gui` vanishes."""
    pyproject = GUI_PATH.parent.parent.parent / "pyproject.toml"
    text = io.open(pyproject, encoding="utf-8").read()
    assert 'openhail-gui = "openhail.gui:main"' in text


def test_gui_client_base64_free_of_bare_except():
    """A bare `except:` hides every error including KeyboardInterrupt.

    The GUI's reader thread must survive malformed lines, but it must not do so
    by swallowing everything indiscriminately.
    """
    tree = ast.parse(io.open(GUI_PATH, encoding="utf-8").read())
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler) and node.type is None:
            raise AssertionError(
                f"bare except at line {node.lineno} in gui.py - catch a specific type"
            )
