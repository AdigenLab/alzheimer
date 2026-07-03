"""Tests for guardrails.py — confirm-bypass via --approve / --dry-run, the
pending one-shot state, the self-allowlist, and the bash-based exec (which fixes
cmd.exe mangling `&&` inside WSL commands on Windows)."""

import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stdout, redirect_stderr

import guardrails


class GuardrailsTestBase(unittest.TestCase):
    def setUp(self):
        # Redirect pending state to a temp file so tests never touch the real
        # install dir.
        self.tmpdir = tempfile.mkdtemp()
        self.pending = os.path.join(self.tmpdir, ".guardrails.pending")
        os.environ["ALZ_PENDING_FILE"] = self.pending

    def tearDown(self):
        os.environ.pop("ALZ_PENDING_FILE", None)
        shutil.rmtree(self.tmpdir, ignore_errors=True)


class TestSelfAllowlist(GuardrailsTestBase):
    def _cmd(self, command):
        return guardrails._is_self_exec("Bash", {"command": command})

    def test_exec_form_allowed(self):
        self.assertTrue(self._cmd('python3 "C:/Projects/alzheimer/guardrails.py" --exec "git push"'))

    def test_approve_form_allowed(self):
        self.assertTrue(self._cmd('python3 "C:/Projects/alzheimer/guardrails.py" --approve'))

    def test_approve_dry_run_allowed(self):
        self.assertTrue(self._cmd('python3 "/home/u/.alzheimer/guardrails.py" --approve --dry-run'))

    def test_cd_prefixed_approve_allowed(self):
        self.assertTrue(self._cmd('cd /tmp && python3 "/x/guardrails.py" --approve'))

    def test_plain_dangerous_command_not_self(self):
        self.assertFalse(self._cmd("git push origin main"))

    def test_embedded_guardrails_string_not_self(self):
        # guardrails.py mentioned mid-command must not be treated as a bypass.
        self.assertFalse(self._cmd('echo "run guardrails.py --approve" && git push'))


class TestRunUsesBash(GuardrailsTestBase):
    @unittest.skipUnless(shutil.which("bash"), "bash not on PATH")
    def test_single_quoted_and_operator_preserved(self):
        # The whole point of _run: a login bash honours single quotes, so `&&`
        # inside them is literal — unlike Windows cmd.exe which would split on it.
        result = guardrails._run("echo 'a && b'")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), "a && b")

    def test_preferred_bash_avoids_wsl_launcher_on_windows(self):
        # On Windows the Bash tool is git-bash (/c/… → C:), NOT the System32 WSL
        # launcher (/mnt/c/…) — picking the latter breaks stored `cd /c/… && …`.
        bash = guardrails._preferred_bash()
        if os.name == "nt" and bash and shutil.which("git"):
            self.assertNotIn("system32", bash.lower())
            self.assertIn("bash", os.path.basename(bash).lower())


class TestPendingLifecycle(GuardrailsTestBase):
    def _rule(self):
        return {"tool": "Bash", "pattern": r"echo", "action": "confirm"}

    def test_arm_and_read_roundtrip(self):
        self.assertTrue(guardrails.arm_pending("echo HELLO", self._rule()))
        p = guardrails.read_pending()
        self.assertIsNotNone(p)
        self.assertEqual(p["command"], "echo HELLO")
        self.assertEqual(p["rule"]["pattern"], "echo")

    def test_approve_nothing_pending(self):
        with self.assertRaises(SystemExit) as cm:
            guardrails.main_approve()
        self.assertEqual(cm.exception.code, 1)

    def test_dry_run_previews_without_running_or_consuming(self):
        guardrails.arm_pending("echo SHOULD_NOT_RUN", self._rule())
        buf = io.StringIO()
        with redirect_stdout(buf), self.assertRaises(SystemExit) as cm:
            guardrails.main_approve(dry_run=True)
        self.assertEqual(cm.exception.code, 0)
        out = buf.getvalue()
        self.assertIn("dry-run", out)
        self.assertIn("echo SHOULD_NOT_RUN", out)
        # Pending must survive a dry-run.
        self.assertTrue(os.path.exists(self.pending))

    def test_approve_runs_and_consumes(self):
        guardrails.arm_pending("echo APPROVED_OK", self._rule())
        buf = io.StringIO()
        with redirect_stdout(buf), self.assertRaises(SystemExit) as cm:
            guardrails.main_approve()
        self.assertEqual(cm.exception.code, 0)
        self.assertIn("APPROVED_OK", buf.getvalue())
        # One-shot: pending consumed.
        self.assertFalse(os.path.exists(self.pending))

    def test_approve_runs_in_recorded_cwd(self):
        # A relative-path write must land in the cwd recorded at arm time,
        # not the process cwd — this is the nested-repo (collector/admin) fix.
        workdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, workdir, ignore_errors=True)
        self.assertTrue(
            guardrails.arm_pending("echo IN_CWD > marker.txt", self._rule(), cwd=workdir)
        )
        with redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as cm:
            guardrails.main_approve()
        self.assertEqual(cm.exception.code, 0)
        self.assertTrue(os.path.exists(os.path.join(workdir, "marker.txt")))
        self.assertFalse(os.path.exists(self.pending))  # one-shot consumed

    def test_approve_propagates_nonzero_exit(self):
        guardrails.arm_pending("exit 7", self._rule())
        with self.assertRaises(SystemExit) as cm:
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                guardrails.main_approve()
        self.assertEqual(cm.exception.code, 7)
        self.assertFalse(os.path.exists(self.pending))

    def test_stale_pending_refused_and_cleared(self):
        guardrails.arm_pending("echo TOO_OLD", self._rule())
        # Backdate the timestamp beyond the TTL.
        with open(self.pending) as f:
            data = json.load(f)
        data["ts"] = time.time() - (guardrails.PENDING_TTL + 60)
        with open(self.pending, "w") as f:
            json.dump(data, f)
        with self.assertRaises(SystemExit) as cm:
            with redirect_stderr(io.StringIO()):
                guardrails.main_approve()
        self.assertEqual(cm.exception.code, 1)
        self.assertFalse(os.path.exists(self.pending))  # stale state cleared


class TestHookArmsPending(GuardrailsTestBase):
    """Integration: run the script as the PreToolUse hook would."""

    def _hook(self, command, cwd=None):
        data = {"tool_name": "Bash", "tool_input": {"command": command}}
        if cwd is not None:
            data["cwd"] = cwd
        payload = json.dumps(data)
        env = {**os.environ, "ALZ_PENDING_FILE": self.pending}
        return subprocess.run(
            [sys.executable, guardrails.__file__],
            input=payload, capture_output=True, text=True, env=env,
        )

    def test_git_push_blocked_and_pending_armed(self):
        r = self._hook("git push origin main")
        self.assertEqual(r.returncode, 0)  # exit 0 so Claude Code parses stdout
        self.assertIn('"permissionDecision": "deny"', r.stdout)
        self.assertIn("--approve", r.stdout)  # the convenient hint is surfaced
        p = guardrails.read_pending()
        self.assertIsNotNone(p)
        self.assertEqual(p["command"], "git push origin main")

    def test_hook_records_cwd_from_payload(self):
        r = self._hook("git push origin main", cwd="/some/where")
        self.assertEqual(r.returncode, 0)
        p = guardrails.read_pending()
        self.assertIsNotNone(p)
        self.assertEqual(p["cwd"], "/some/where")

    def test_self_approve_invocation_allowed_by_hook(self):
        r = self._hook('python3 "/x/guardrails.py" --approve')
        self.assertEqual(r.returncode, 0)
        self.assertEqual(r.stdout.strip(), "")  # allowed → no deny JSON

    def test_safe_command_allowed_no_pending(self):
        r = self._hook("ls -la")
        self.assertEqual(r.stdout.strip(), "")
        self.assertIsNone(guardrails.read_pending())


if __name__ == "__main__":
    unittest.main()
