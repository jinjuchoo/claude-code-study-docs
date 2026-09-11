#!/usr/bin/env python3
"""Claude Code PreToolUse guard for a narrow Bash allowlist."""
import json
import re
import shlex
import sys


def block(reason: str) -> None:
    print(f"Blocked: {reason}", file=sys.stderr)
    raise SystemExit(2)


try:
    payload = json.load(sys.stdin)
except (json.JSONDecodeError, UnicodeDecodeError) as exc:
    block(f"Hook 입력 JSON을 해석할 수 없습니다: {exc}")

if not isinstance(payload, dict):
    block("Hook 입력은 JSON 객체여야 합니다")
tool_input = payload.get("tool_input")
if not isinstance(tool_input, dict):
    block("tool_input 객체가 없습니다")
command = tool_input.get("command")
if not isinstance(command, str) or not command.strip():
    block("tool_input.command가 없거나 비어 있습니다")
if len(command) > 4096:
    block("명령이 4096자를 넘습니다")
if any(ch in command for ch in "\r\n\x00"):
    block("제어 문자를 허용하지 않습니다")
if any(ch in command for ch in "$`*?[]~{}"):
    block("변수·명령·글로브 확장을 허용하지 않습니다")

try:
    lexer = shlex.shlex(command, posix=True, punctuation_chars="|&;<>")
    lexer.whitespace_split = True
    lexer.commenters = ""
    argv = list(lexer)
except ValueError as exc:
    block(f"셸 토큰을 해석할 수 없습니다: {exc}")

if not argv:
    block("실행할 명령이 없습니다")
if any(token and set(token) <= set("|&;<>") for token in argv):
    block("파이프·체인·리다이렉션을 허용하지 않습니다")


def options(args, flags=(), values=None, patterns=()) -> list[str]:
    values = values or {}
    end = False
    i = 0
    operands = []
    while i < len(args):
        arg = args[i]
        if end or not arg.startswith("-") or arg == "-":
            operands.append(arg)
            i += 1
            continue
        if arg == "--":
            end = True
            i += 1
            continue
        if arg in flags or any(re.fullmatch(p, arg) for p in patterns):
            i += 1
            continue
        name, sep, value = arg.partition("=")
        if name in values:
            if not sep:
                i += 1
                if i >= len(args):
                    block(f"{name} 옵션 값이 없습니다")
                value = args[i]
            if not re.fullmatch(values[name], value):
                block(f"{name} 옵션 값이 허용 범위를 벗어났습니다: {value}")
            i += 1
            continue
        block(f"허용하지 않은 옵션입니다: {arg}")
    return operands


cmd, args = argv[0], argv[1:]
if cmd == "git":
    if not args:
        block("git 하위 명령이 없습니다")
    sub, args = args[0], args[1:]
    git_flags = {
        "diff": ("--cached", "--staged", "--stat", "--name-only", "--name-status", "--no-color", "--no-ext-diff", "--minimal", "-w", "--ignore-all-space", "--ignore-space-change", "--exit-code", "--quiet"),
        "log": ("--oneline", "--stat", "--name-only", "--name-status", "--no-color", "--decorate", "--no-decorate", "--all"),
        "show": ("--stat", "--name-only", "--name-status", "--no-color", "--no-ext-diff"),
        "status": ("--short", "--porcelain", "--branch", "--no-ahead-behind"),
        "blame": ("--line-porcelain", "--porcelain", "-w"),
    }
    if sub not in git_flags:
        block(f"허용하지 않은 git 하위 명령입니다: {sub}")
    values = {}
    patterns = ()
    if sub == "log":
        values = {"--max-count": r"[0-9]+", "-n": r"[0-9]+"}
        patterns = (r"-[0-9]+",)
    elif sub == "status":
        values = {"--untracked-files": r"(?:no|normal|all)"}
    elif sub == "blame":
        values = {"-L": r"[0-9]+(?:,[0-9]+)?"}
    options(args, git_flags[sub], values, patterns)
elif cmd in {"cat", "head", "tail", "ls", "wc", "sort", "uniq", "jq"}:
    specs = {
        "cat": (("-n", "-b", "-s"), {}, ()),
        "head": (("-q", "-v"), {"-n": r"[0-9]+", "--lines": r"[0-9]+"}, (r"-[0-9]+",)),
        "tail": (("-q", "-v"), {"-n": r"[+]?[0-9]+", "--lines": r"[+]?[0-9]+"}, (r"-[0-9]+",)),
        "ls": (("-l", "-a", "-la", "-al", "-h", "-lh", "-hl", "-R", "-d", "-1"), {}, ()),
        "wc": (("-l", "-w", "-c", "-m"), {}, ()),
        "sort": (("-n", "-r", "-u", "-f", "-b"), {}, ()),
        "uniq": (("-c", "-d", "-u", "-i"), {}, ()),
        "jq": (("-r", "-c", "-M", "-S", "-e", "-s"), {}, ()),
    }
    options(args, *specs[cmd])
elif cmd == "npm":
    if not args or args[0] != "audit":
        block("npm은 audit 하위 명령만 허용합니다")
    if options(args[1:], ("--json",), {"--audit-level": r"(?:info|low|moderate|high|critical)", "--omit": r"(?:dev|optional|peer)"}):
        block("npm audit에는 위치 인자를 허용하지 않습니다")
elif cmd == "pip-audit":
    if options(args, ("--desc", "--aliases"), {"--format": r"(?:columns|json|cyclonedx-json|cyclonedx-xml|markdown)", "-r": r"[^\x00-\x1f]+"}):
        block("pip-audit에는 위치 인자를 허용하지 않습니다")
elif cmd == "trivy":
    if not args or args[0] != "fs":
        block("trivy는 fs 스캔만 허용합니다")
    targets = options(args[1:], ("--no-progress",), {"--format": r"(?:table|json)", "--severity": r"(?:UNKNOWN|LOW|MEDIUM|HIGH|CRITICAL)(?:,(?:UNKNOWN|LOW|MEDIUM|HIGH|CRITICAL))*", "--scanners": r"(?:vuln|misconfig|secret|license)(?:,(?:vuln|misconfig|secret|license))*"})
    if len(targets) != 1:
        block("trivy fs에는 스캔 경로 하나만 허용합니다")
else:
    block(f"허용하지 않은 명령입니다: {cmd}")

raise SystemExit(0)
