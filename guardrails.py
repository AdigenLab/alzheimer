#!/usr/bin/env python3
"""
guardrails.py — Fixes permission drift in Claude Code.

Hard layer of the Alzheimer guardrails system. When Claude stops asking
before taking risky actions (the "yes, yes, yes" drift pattern), this
hook catches what Claude forgot. Pattern-matches tool invocations against
configurable rules and blocks those that match by exiting non-zero.

The hook receives tool information as JSON on stdin:
    {"tool_name": "Bash", "tool_input": {"command": "git push origin main"}}

Exit 0 to allow. To block: emit hookSpecificOutput deny JSON on stdout,
error message on stderr, and exit 2 (belt-and-suspenders per #37210).

Three action types:
  - "allow": no rule matched — tool call proceeds
  - "block": always rejected — user must edit config to remove
  - "confirm": blocked on first attempt; approved execution via --exec
    mode, which temporarily removes the rule, runs the command, and
    re-adds the rule in a try/finally block — guaranteeing restoration

The safety-critical step (restoring the guardrail after execution) is
deterministic Python code, not a behavioral promise subject to drift.
"""

import json
import os
import re
import shutil
import subprocess
import sys
import time

# --- UTF-8 file I/O shim — fix for UnicodeDecodeError on non-UTF-8 OS locales (e.g. Windows cp1251) ---
import builtins as _builtins
_std_open = _builtins.open
def open(*args, **kwargs):  # noqa: A001 — intentional builtins.open override (text mode only)
    _mode = kwargs.get("mode", args[1] if len(args) > 1 else "r")
    if "b" not in _mode:
        kwargs.setdefault("encoding", "utf-8")
    return _std_open(*args, **kwargs)

# Ensure stdin can be READ and stdout/stderr can emit non-ASCII on
# non-UTF-8 consoles (e.g. Windows cp1251/cp1252). The PreToolUse payload
# arrives as UTF-8 JSON on stdin; without reconfiguring stdin the locale
# codec mis-decodes a non-ASCII command and json.load raises
# UnicodeDecodeError (a ValueError subclass) — which main_hook's fail-open
# except would catch, silently allowing a command the guardrail should block.
for _stream in (sys.stdin, sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8")
    except Exception:
        pass


# ── Default rules ─────────────────────────────────────────────────────

# Each rule matches a tool name and a regex pattern against the tool
# input.  If both match, the action is taken.
#
# For Bash tools, the pattern is matched against the "command" field.
# For other tools, it is matched against the full JSON-serialized input.
DEFAULT_RULES = [
    {
        "tool": "Bash",
        "pattern": r"git\s+push\b",
        "action": "confirm",
        "message": (
            "git push requires user confirmation (Alzheimer guardrails). "
            "Ask the user for explicit permission before pushing."
        ),
    },
    {
        "tool": "Bash",
        "pattern": r"git\s+push\s+.*--force\b",
        "action": "confirm",
        "message": (
            "git push --force requires user confirmation (Alzheimer guardrails). "
            "This is a destructive operation. Ask the user first."
        ),
    },
    {
        "tool": "Bash",
        "pattern": r"git\s+reset\s+--hard\b",
        "action": "confirm",
        "message": (
            "git reset --hard requires user confirmation (Alzheimer guardrails). "
            "This discards uncommitted changes. Ask the user first."
        ),
    },
    {
        "tool": "Bash",
        "pattern": r"git\s+branch\s+-[dD]\b",
        "action": "confirm",
        "message": (
            "Branch deletion requires user confirmation (Alzheimer guardrails). "
            "Ask the user for explicit permission."
        ),
    },
    {
        "tool": "Bash",
        "pattern": r"rm\s+-r[f ]\s*/\s*$|rm\s+-r[f ]\s*/\s+",
        "action": "block",
        "message": (
            "Recursive delete of root (/) is blocked by Alzheimer guardrails."
        ),
    },
    {
        "tool": "Bash",
        "pattern": r"gh\s+issue\s+comment\b",
        "action": "confirm",
        "message": (
            "Posting a GitHub comment requires user confirmation "
            "(Alzheimer guardrails). Draft the comment, show it to "
            "the user, and wait for explicit permission before posting. "
            "Public comments are permanent and visible."
        ),
    },
    {
        "tool": "Bash",
        "pattern": r"gh\s+issue\s+create\b",
        "action": "confirm",
        "message": (
            "Creating a GitHub issue requires user confirmation "
            "(Alzheimer guardrails). Draft the issue, show it to "
            "the user, and wait for explicit permission before filing. "
            "Public issues are permanent and visible."
        ),
    },
    {
        "tool": "Bash",
        "pattern": r"gh\s+pr\s+comment\b",
        "action": "confirm",
        "message": (
            "Posting a GitHub PR comment requires user confirmation "
            "(Alzheimer guardrails). Draft the comment, show it to "
            "the user, and wait for explicit permission before posting. "
            "Public comments are permanent and visible."
        ),
    },
    {
        "tool": "Bash",
        "pattern": r"gh\s+pr\s+create\b",
        "action": "confirm",
        "message": (
            "Creating a GitHub PR requires user confirmation "
            "(Alzheimer guardrails). Draft the PR, show it to "
            "the user, and wait for explicit permission before creating. "
            "Public PRs are permanent and visible."
        ),
    },
]

# Config file for custom rules (loaded from alzheimer install dir).
CONFIG_FILE = ".guardrails.conf"

# Pending-approval state. When the hook blocks a "confirm" command, it records
# that EXACT command here so `--approve` can re-run it verbatim — no re-typing,
# no re-quoting, no Windows->WSL quoting hell. One-shot (consumed on approve) and
# TTL-bounded (a stale pending is refused, so an old/forgotten command can't be
# replayed). Path overridable via $ALZ_PENDING_FILE (tests).
PENDING_FILE = ".guardrails.pending"
PENDING_TTL = 300  # seconds; pending older than this is stale and refused


# ── Rule loading ──────────────────────────────────────────────────────

def _alzheimer_dir():
    """Return the directory containing this script."""
    return os.path.dirname(os.path.abspath(__file__))


def load_rules():
    """Load rules from config file, falling back to defaults.

    Config format (.guardrails.conf):
    {
        "rules": [
            {"tool": "Bash", "pattern": "git\\s+push\\b", "action": "block",
             "message": "..."}
        ]
    }

    If the config file contains a "rules" key, those rules REPLACE the
    defaults entirely.  If it contains "extra_rules", those are APPENDED
    to the defaults.
    """
    config_path = os.path.join(_alzheimer_dir(), CONFIG_FILE)
    if not os.path.exists(config_path):
        return list(DEFAULT_RULES)

    try:
        with open(config_path) as f:
            config = json.load(f)
    except (json.JSONDecodeError, OSError):
        # Bad config — fall back to defaults.
        return list(DEFAULT_RULES)

    if "rules" in config:
        return config["rules"]
    elif "extra_rules" in config:
        return list(DEFAULT_RULES) + config["extra_rules"]
    else:
        return list(DEFAULT_RULES)


# ── Matching ──────────────────────────────────────────────────────────

def get_match_text(tool_name, tool_input):
    """Extract the text to match against from the tool input.

    For Bash tools, match against the command string with single-quoted
    strings neutralized to prevent false positives (e.g., matching 'gh'
    inside: echo 'gh repo create ...' | clip.exe).
    For other tools, match against the JSON-serialized input.
    """
    if tool_name == "Bash":
        cmd = tool_input.get("command", "")
        # Neutralize heredoc content: message bodies (git commit -m),
        # not commands. Matches <<EOF...EOF, <<'EOF'...EOF, etc.
        cmd = re.sub(r"<<-?['\"]?(\w+)['\"]?\n.*?\n\1\b", '""', cmd, flags=re.DOTALL)
        # Neutralize single-quoted strings: their content is literal
        # in bash (no expansion), so commands inside them are just text.
        cmd = re.sub(r"'[^']*'", "''", cmd)
        return cmd
    return json.dumps(tool_input)


def _is_self_exec(tool_name, tool_input):
    """Check if this is a guardrails.py --exec / --approve invocation (self-allowlist).

    The PreToolUse hook fires on EVERY Bash call, including our own bypass
    invocations. Without this allowlist the bypass would be blocked by the very
    guard it is trying to lift, so it must recognize both --exec and --approve.
    """
    if tool_name != "Bash":
        return False
    command = tool_input.get("command", "").strip()
    # Strip leading "cd <path> &&" — Claude often generates this pattern.
    # cd is non-destructive, so stripping it is safe for matching purposes.
    command = re.sub(r'^cd\s+\S+\s*&&\s*', '', command).strip()
    # Match both direct and python-prefixed invocations:
    #   python3 "/path/to/guardrails.py" --exec "..."
    #   python3 "/path/to/guardrails.py" --approve [--dry-run]
    #   ~/.alzheimer/guardrails.py --approve
    # Anchored to start of command to prevent matching embedded strings.
    return bool(re.match(
        r'["\']?(?:python3?\s+["\']?)?[^\s"\']*guardrails\.py["\']?\s+--(?:exec|approve)\b',
        command
    ))


def check_rules(tool_name, tool_input, rules=None):
    """Check tool invocation against rules.

    Returns (allowed, message) where allowed is True if the action
    should proceed, and message is the block reason if not.
    """
    # Self-allowlist: guardrails.py --exec invocations bypass all rules.
    if _is_self_exec(tool_name, tool_input):
        return True, ""

    if rules is None:
        rules = load_rules()

    match_text = get_match_text(tool_name, tool_input)

    for rule in rules:
        rule_tool = rule.get("tool", "")
        if rule_tool and rule_tool != tool_name:
            continue

        pattern = rule.get("pattern", "")
        if not pattern:
            continue

        try:
            if re.search(pattern, match_text):
                action = rule.get("action", "block")
                if action == "block":
                    message = rule.get(
                        "message",
                        f"Operation blocked by Alzheimer guardrails "
                        f"(matched: {pattern})"
                    )
                    return False, message
                elif action == "confirm":
                    message = rule.get(
                        "message",
                        f"Operation requires user confirmation "
                        f"(matched: {pattern})"
                    )
                    message += (
                        " Use guardrails.py --exec to run after "
                        "obtaining user approval."
                    )
                    return False, message
        except re.error:
            # Invalid regex in rule — skip it.
            continue

    return True, ""


# ── Config file manipulation ─────────────────────────────────────────

def _config_path():
    """Return path to .guardrails.conf."""
    return os.path.join(_alzheimer_dir(), CONFIG_FILE)


# ── Pending-approval state (one-shot bypass of the last blocked command) ──────

def _pending_path():
    """Return path to .guardrails.pending ($ALZ_PENDING_FILE overrides for tests)."""
    return os.environ.get("ALZ_PENDING_FILE") or os.path.join(_alzheimer_dir(), PENDING_FILE)


def arm_pending(command, rule, cwd=None):
    """Record the blocked command so --approve can re-run it verbatim. Best-effort.

    `cwd` is the working directory the Bash tool ran the command in (from the
    PreToolUse payload). It is stored so --approve replays the command in that
    SAME directory — the approve process starts in the session cwd, which for a
    nested repo (collector, admin) differs from where the command was issued,
    so without this the replay would target the wrong repo.
    """
    try:
        with open(_pending_path(), "w") as f:
            json.dump({"command": command, "rule": rule, "cwd": cwd, "ts": time.time()}, f)
        return True
    except OSError:
        return False


def read_pending():
    """Return the pending dict, or None if absent/unreadable."""
    path = _pending_path()
    if not os.path.exists(path):
        return None
    try:
        with open(path) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def clear_pending():
    """Remove the pending file (one-shot consume). Best-effort."""
    try:
        os.remove(_pending_path())
    except OSError:
        pass


def _load_config():
    """Load config file, returning (config_dict, existed)."""
    path = _config_path()
    if not os.path.exists(path):
        return {}, False
    try:
        with open(path) as f:
            return json.load(f), True
    except (json.JSONDecodeError, OSError):
        return {}, False


def _save_config(config):
    """Write config dict to .guardrails.conf."""
    path = _config_path()
    with open(path, "w") as f:
        json.dump(config, f, indent=2)
        f.write("\n")


def remove_rule(rule):
    """Remove a rule from .guardrails.conf. Returns True if removed."""
    config, existed = _load_config()
    key = "rules" if "rules" in config else "extra_rules"
    rules = config.get(key, [])

    # Match by tool + pattern + action.
    original_len = len(rules)
    rules = [
        r for r in rules
        if not (r.get("tool") == rule.get("tool")
                and r.get("pattern") == rule.get("pattern")
                and r.get("action") == rule.get("action"))
    ]
    if len(rules) == original_len:
        return False

    config[key] = rules
    _save_config(config)
    return True


def add_rule(rule):
    """Add a rule to .guardrails.conf."""
    config, _ = _load_config()
    key = "rules" if "rules" in config else "extra_rules"
    rules = config.get(key, [])
    rules.append(rule)
    config[key] = rules
    _save_config(config)


def _preferred_bash():
    """Locate the SAME bash Claude's Bash tool uses — not just the first on PATH.

    On Windows that is Git-for-Windows bash (where `/c/…` maps to C:), derived from
    git's install dir. `shutil.which("bash")` there returns System32\\bash.exe (the
    WSL launcher), whose `/mnt/c/…` mapping differs — so a stored `cd /c/… && …`
    command (written by the git-bash Bash tool) fails with "No such file or
    directory". On Unix the plain bash on PATH is already correct.
    """
    if os.name == "nt":
        git = shutil.which("git")
        if git:
            root = os.path.dirname(os.path.dirname(os.path.abspath(git)))
            for cand in (os.path.join(root, "bin", "bash.exe"),
                         os.path.join(root, "usr", "bin", "bash.exe")):
                if os.path.isfile(cand):
                    return cand
    return shutil.which("bash")


def _run(command, cwd=None):
    """Run a shell command the way Claude's Bash tool does — via a login bash —
    so the approved command sees the same PATH/env/aliases (wsl, ssh aliases…) and
    path mapping (`/c/…`).

    `cwd`, when given, is the directory to run in (the Bash tool's working dir,
    captured from the hook payload). A separately-spawned approve process does NOT
    inherit the Bash tool's persistent cwd, so replaying without it targets the
    session cwd — the wrong repo for nested checkouts. When None, inherit as before.

    Critically this avoids cmd.exe on Windows: `subprocess.run(cmd, shell=True)`
    there uses cmd.exe, which ignores single quotes and SPLITS on `&&` — mangling
    `wsl -- bash -lc 'cd … && git push …'` into two broken commands. A login bash
    honours the quoting; _preferred_bash() makes sure it's the right bash (git-bash
    on Windows, not WSL bash). Falls back to shell=True only if no bash is found.

    Returns a CompletedProcess.
    """
    # A cwd that no longer exists would make subprocess.run raise; ignore it then.
    run_cwd = cwd if (cwd and os.path.isdir(cwd)) else None
    bash = _preferred_bash()
    if bash:
        try:
            return subprocess.run(
                [bash, "-lc", command], capture_output=True, text=True,
                encoding="utf-8", errors="replace", cwd=run_cwd,
            )
        except (FileNotFoundError, OSError):
            pass
    return subprocess.run(
        command, shell=True, capture_output=True, text=True,
        encoding="utf-8", errors="replace", cwd=run_cwd,
    )


def exec_with_temporary_allow(command, rule, cwd=None):
    """Remove rule, run command, re-add rule. Guaranteed by try/finally.

    Returns (returncode, stdout, stderr).
    """
    removed = remove_rule(rule)
    try:
        result = _run(command, cwd=cwd)
        return result.returncode, result.stdout, result.stderr
    finally:
        if removed:
            add_rule(rule)


def find_matching_rule(command):
    """Find the first confirm rule that matches a command.

    Returns the rule dict, or None if no confirm rule matches.
    """
    rules = load_rules()
    for rule in rules:
        rule_tool = rule.get("tool", "")
        if rule_tool and rule_tool != "Bash":
            continue
        pattern = rule.get("pattern", "")
        action = rule.get("action", "block")
        if action != "confirm" or not pattern:
            continue
        try:
            if re.search(pattern, command):
                return rule
        except re.error:
            continue
    return None


# ── Main ──────────────────────────────────────────────────────────────

def main():
    """Entry point. Dispatches to hook / --exec / --approve mode."""
    args = sys.argv[1:]
    if args and args[0] == "--exec" and len(sys.argv) >= 3:
        main_exec(" ".join(sys.argv[2:]))
    elif args and args[0] == "--approve":
        main_approve(dry_run="--dry-run" in args)
    else:
        main_hook()


def main_hook():
    """Read tool info from stdin, check against rules, exit accordingly."""
    try:
        data = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        # Can't parse input — allow by default (fail open).
        sys.exit(0)

    tool_name = data.get("tool_name", "")
    tool_input = data.get("tool_input", {})
    hook_cwd = data.get("cwd")  # dir the Bash tool ran in — replay --approve here

    allowed, message = check_rules(tool_name, tool_input)

    if allowed:
        sys.exit(0)
    else:
        # If a CONFIRM rule matched (not a hard block), arm the pending state so
        # the human-approved command can be re-run verbatim via --approve, and
        # surface that ready-to-copy command in the deny reason.
        if tool_name == "Bash":
            command = tool_input.get("command", "")
            rule = find_matching_rule(command)  # only returns confirm rules
            if rule is not None and arm_pending(command, rule, cwd=hook_cwd):
                approve_cmd = f'python3 "{os.path.abspath(__file__)}" --approve'
                message += (
                    f" Or, after the user approves, run: {approve_cmd} "
                    f"— re-runs THIS exact command once (within {PENDING_TTL // 60} min); "
                    f"add --dry-run to preview first."
                )
        # Block the tool call using both mechanisms for maximum reliability:
        # 1. Structured deny JSON on stdout (canonical protocol per #37210).
        # Exit 0 so Claude Code parses stdout. Exit 2 causes stdout to be
        # ignored, silently allowing the blocked command through.
        deny = json.dumps({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": message,
            }
        })
        print(deny)  # stdout — parsed by Claude Code at exit 0
        sys.exit(0)


def main_exec(command):
    """Execute a command with temporary rule removal (confirm mode).

    Finds the matching confirm rule, removes it, runs the command,
    and re-adds the rule in a try/finally block.
    """
    rule = find_matching_rule(command)
    if rule is None:
        # No confirm rule matches — just run it directly.
        result = _run(command)
        if result.stdout:
            print(result.stdout, end="")
        if result.stderr:
            print(result.stderr, end="", file=sys.stderr)
        sys.exit(result.returncode)

    returncode, stdout, stderr = exec_with_temporary_allow(command, rule)
    if stdout:
        print(stdout, end="")
    if stderr:
        print(stderr, end="", file=sys.stderr)
    sys.exit(returncode)


def main_approve(dry_run=False):
    """Re-run the most-recently-blocked confirm command, verbatim, one-shot.

    The hook stored the exact command (no re-typing/re-quoting needed). We verify
    it is fresh (TTL), then either preview it (--dry-run) or run it through the
    temporary-rule-lift wrapper and consume the pending state. This is the
    convenient, low-error path to clear a confirm guard after the user approves.
    """
    pending = read_pending()
    if pending is None:
        print(
            "Nothing pending to approve — no command was recently blocked "
            "(or the pending state was already consumed).",
            file=sys.stderr,
        )
        sys.exit(1)

    command = pending.get("command", "")
    rule = pending.get("rule")
    cwd = pending.get("cwd")  # replay in the dir the command was issued in
    age = time.time() - float(pending.get("ts", 0) or 0)

    if not command:
        clear_pending()
        print("Pending command was empty; cleared.", file=sys.stderr)
        sys.exit(1)

    if age > PENDING_TTL:
        clear_pending()
        print(
            f"Pending command is stale ({int(age)}s old > {PENDING_TTL}s TTL) and "
            f"was refused. Re-run the original command to re-arm, then --approve.",
            file=sys.stderr,
        )
        sys.exit(1)

    if dry_run:
        pattern = rule.get("pattern") if isinstance(rule, dict) else None
        print(f"[dry-run] Pending ({int(age)}s old) — would run verbatim:")
        print(f"  {command}")
        if cwd:
            print(f"[dry-run] In directory: {cwd}")
        if pattern:
            print(f"[dry-run] Guard temporarily lifted for rule: {pattern}")
        print("[dry-run] NOT executed; pending kept. Re-run without --dry-run to execute.")
        sys.exit(0)

    try:
        if isinstance(rule, dict):
            returncode, stdout, stderr = exec_with_temporary_allow(command, rule, cwd=cwd)
        else:
            result = _run(command, cwd=cwd)
            returncode, stdout, stderr = result.returncode, result.stdout, result.stderr
    finally:
        clear_pending()  # one-shot: consume regardless of outcome

    if stdout:
        print(stdout, end="")
    if stderr:
        print(stderr, end="", file=sys.stderr)
    sys.exit(returncode)


if __name__ == "__main__":
    main()
