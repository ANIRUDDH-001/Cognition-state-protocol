"""Terminal output helpers.

The demo is judged live on a Windows console. Python defaults stdout to cp1252
there, so a stray '∩' raises UnicodeEncodeError mid-narration and kills the run.
We force UTF-8 and enable ANSI once, at entry, and stay close to ASCII anyway.
"""
from __future__ import annotations

import os
import sys

C = {
    "hd": "\033[1;36m",
    "b": "\033[1m",
    "ok": "\033[32m",
    "warn": "\033[33m",
    "bad": "\033[31m",
    "dim": "\033[90m",
    "cy": "\033[36m",
    "mg": "\033[35m",
    "x": "\033[0m",
}

OK = "[OK]"
NO = "[XX]"


def setup(no_color: bool = False) -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    if os.name == "nt":
        # Ask conhost for ANSI. Windows Terminal already does it; old consoles need this.
        try:
            import ctypes

            k = ctypes.windll.kernel32
            k.SetConsoleMode(k.GetStdHandle(-11), 7)
        except Exception:
            pass
    if no_color or os.environ.get("NO_COLOR"):
        for k in C:
            C[k] = ""


def banner(title: str, width: int = 78) -> None:
    print(f"\n{C['hd']}{'=' * width}\n  {title}\n{'=' * width}{C['x']}")


def rule(title: str = "", width: int = 78) -> None:
    print(f"{C['dim']}{('-- ' + title + ' ').ljust(width, '-') if title else '-' * width}{C['x']}")


def kv(key: str, value, pad: int = 16) -> None:
    print(f"  {key:<{pad}}: {value}")
