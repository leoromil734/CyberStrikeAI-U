"""Offline wrapper tests: fake systemd/children, fake time, temporary artifacts only."""

import csv
import hashlib
import io
import json
import os
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from pathlib import Path
import signal
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts.recon import candidate_inventory as inventory
from scripts.recon import jsapiscan_runner as runner


class FakeClock:
    def __init__(self):
        self.now = 0.0

    def monotonic(self):
        return self.now

    def wait(self, seconds):
        self.now += seconds
        return False


class FakeProcess:
    def __init__(self, clock, duration, code=0, ignore_terminate=False):
        self.clock, self.started, self.duration = clock, clock.now, duration
        self.code, self.returncode, self.ignore_terminate = code, None, ignore_terminate
        self.terminated, self.killed = False, False

    def poll(self):
        if self.returncode is None and self.clock.now - self.started >= self.duration:
            self.returncode = self.code
        return self.returncode

    def terminate(self):
        self.terminated = True
        if not self.ignore_terminate:
            self.returncode = -15

    def kill(self):
        self.killed = True
        self.returncode = -9

    def wait(self, timeout):
        if self.poll() is None:
            raise subprocess.TimeoutExpired("fake-process", timeout)
        return self.returncode


class JSAPIscanRunnerTests(unittest.TestCase):
    def setUp(self):
        environment = patch.dict(runner.os.environ)
        environment.start()
        self.addCleanup(environment.stop)  # unittest.enterContext requires Python 3.11+.
        for name in ("CSAI_EXECUTION_ID", "CSAI_WORKSPACE_SANDBOX", "CSAI_ARTIFACT_DIR"):
            runner.os.environ.pop(name, None)

    def args(self, *values):
        with redirect_stderr(io.StringIO()):
            return runner.make_parser().parse_args(list(values))

    def fake_environment(self, stack, root, clock, duration=0, code=0, result="success", cancellation=None, callback=None, ignore_terminate=False, workspace=False):
        binary = root / "verified-binary"
        binary.write_bytes(b"fixture binary")
        account = SimpleNamespace(pw_uid=997, pw_gid=997)
        children, commands, control_calls, batches = [], [], [], []
        stack.enter_context(patch.object(runner, "BINARY", binary))
        stack.enter_context(patch.object(runner, "BINARY_SHA256", hashlib.sha256(b"fixture binary").hexdigest()))
        stack.enter_context(patch.object(runner, "RUN_ROOT", root / "runs"))
        stack.enter_context(patch.object(runner.sys, "platform", "linux"))
        stack.enter_context(patch.object(runner, "pwd", SimpleNamespace(getpwnam=lambda _name: account)))
        stack.enter_context(patch.object(runner.os, "geteuid", return_value=0, create=True))
        ownership = stack.enter_context(patch.object(runner.os, "chown", create=True))
        if workspace:
            self.workspace_context(stack, root)
            stack.enter_context(patch.dict(runner.os.environ, CSAI_ARTIFACT_DIR=str(root)))
            stack.enter_context(patch.object(runner, "pwd", None))
        stack.enter_context(patch.object(runner.time, "monotonic", side_effect=clock.monotonic))
        if cancellation:
            stack.enter_context(patch.object(cancellation, "wait", side_effect=clock.wait))

        def popen(command, **kwargs):
            commands.append(command)
            target_file = Path(command[command.index("-f") + 1])
            batches.append(target_file.read_text("utf-8").splitlines())
            work = Path(kwargs["cwd"]) if workspace else Path(next(value.split("=", 1)[1] for value in command if value.startswith("WorkingDirectory=")))
            self.assertTrue(kwargs["start_new_session"])
            if callback:
                callback(work, kwargs)
            child = FakeProcess(clock, duration, code, ignore_terminate)
            child.pid = 900000 + len(children)
            children.append(child)
            return child

        def killpg(pid, signum):
            child = next(child for child in children if child.pid == pid)
            if signum == signal.SIGTERM:
                child.terminate()
            else:
                child.kill()
        groups = stack.enter_context(patch.object(runner.os, "killpg", side_effect=killpg, create=True))

        def systemctl(command, **_kwargs):
            self.assertEqual(command[0], "/usr/bin/systemctl")
            control_calls.append(command)
            return SimpleNamespace(returncode=0, stdout=result if command[1] == "show" else "")

        launcher = stack.enter_context(patch.object(runner.subprocess, "Popen", side_effect=popen))
        controls = stack.enter_context(patch.object(runner.subprocess, "run", side_effect=systemctl))
        return SimpleNamespace(children=children, commands=commands, control_calls=control_calls, batches=batches,
                               launcher=launcher, controls=controls, account=account, ownership=ownership, groups=groups)

    def workspace_context(self, stack, root):
        stack.enter_context(patch.dict(runner.os.environ, CSAI_WORKSPACE_SANDBOX="1"))
        stack.enter_context(patch.object(runner.sys, "platform", "linux"))
        stack.enter_context(patch.object(runner.signal, "SIGKILL", 9, create=True))
        for name in ("getuid", "geteuid", "getgid", "getegid"):
            stack.enter_context(patch.object(runner.os, name, return_value=997, create=True))
        stack.enter_context(patch.object(runner.os, "getpid", return_value=42))
        context = {
            Path("/proc/1/status"): "Name:\tbwrap\nPid:\t1\nPPid:\t0\nNSpid:\t1\n",
            Path("/proc/self/uid_map"): "997 997 1\n",
            Path("/proc/self/gid_map"): "997 997 1\n",
            Path("/proc/self/status"): "Pid:\t42\nNSpid:\t42\nUid:\t997 997 997 997\nGid:\t997 997 997 997\nNoNewPrivs:\t1\n" + "".join(name + ":\t0000000000000000\n" for name in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")),
        }
        read_text, exists = Path.read_text, Path.exists
        stack.enter_context(patch.object(Path, "exists", lambda path: False if path in (Path("/run/systemd"), Path("/run/dbus")) else exists(path)))
        stack.enter_context(patch.object(Path, "read_text", lambda path, *args, **kwargs: context[path] if path in context else read_text(path, *args, **kwargs)))
        mounts = {Path("/"): ("tmpfs", {"ro", "nosuid", "nodev"}), Path("/proc"): ("proc", {"rw"}),
                  Path("/usr"): ("ext4", {"ro"}), runner.BINARY.resolve(): ("ext4", {"ro"}),
                  Path(runner.__file__).resolve(): ("ext4", {"ro"}), Path(runner.sys.executable).resolve(): ("ext4", {"ro"}),
                  root: ("ext4", {"rw"})}
        stack.enter_context(patch.object(runner, "_workspace_nproc_enforced", return_value=True))
        stack.enter_context(patch.object(runner, "_workspace_mounts", return_value=mounts))
        return context, mounts

    def manifest(self, root):
        job = next((root / "runs").iterdir())
        return json.loads((job / "manifest.json").read_text("utf-8")), job

    def test_workspace_context_requires_kernel_evidence_not_just_marker(self):
        for failure in (None, "marker", "host_uid_map", "multiple_ids", "uid_mismatch", "gid_map", "capabilities", "privileges", "root_rw", "root_ext4", "proc", "runtime_rw", "root_mapping", "unreadable"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temp, ExitStack() as stack:
                context, mounts = self.workspace_context(stack, Path(temp))
                if failure == "marker":
                    runner.os.environ["CSAI_WORKSPACE_SANDBOX"] = "true"
                elif failure == "host_uid_map":
                    context[Path("/proc/self/uid_map")] = "0 0 4294967295\n"
                elif failure == "multiple_ids":
                    context[Path("/proc/self/uid_map")] += "998 998 1\n"
                elif failure == "uid_mismatch":
                    context[Path("/proc/self/uid_map")] = "998 998 1\n"
                elif failure == "gid_map":
                    context[Path("/proc/self/gid_map")] = "0 0 4294967295\n"
                elif failure == "capabilities":
                    context[Path("/proc/self/status")] += "CapBnd:\t0000000000000001\n"
                elif failure == "privileges":
                    context[Path("/proc/self/status")] += "NoNewPrivs:\t0\n"
                elif failure == "root_rw":
                    mounts[Path("/")] = ("tmpfs", {"rw", "nosuid", "nodev"})
                elif failure == "root_ext4":
                    mounts[Path("/")] = ("ext4", {"ro", "nosuid", "nodev"})
                elif failure == "proc":
                    mounts[Path("/proc")] = ("ext4", {"rw"})
                elif failure == "runtime_rw":
                    mounts[runner.BINARY.resolve()] = ("ext4", {"rw"})
                elif failure == "root_mapping":
                    context[Path("/proc/self/uid_map")] = "997 0 1\n"
                    stack.enter_context(patch.object(runner, "_workspace_nproc_enforced", return_value=False))
                elif failure == "unreadable":
                    stack.enter_context(patch.object(Path, "read_text", side_effect=PermissionError))
                if failure:
                    with self.assertRaises(runner.InputError) as raised:
                        runner._workspace_sandbox()
                    self.assertIn(raised.exception.code, ("untrusted_workspace_sandbox_context", "workspace_resource_limits_require_nonroot_uid_mapping"))
                else:
                    self.assertTrue(runner._workspace_sandbox())
        with patch.dict(runner.os.environ, {}, clear=True), patch.object(Path, "read_text", side_effect=AssertionError):
            self.assertFalse(runner._workspace_sandbox())

    def test_host_nonroot_identity_maps_still_require_all_isolation_checks(self):
        for failure in (None, "host_init", "wrong_pid", "host_proc", "init_parent", "root_uid", "saved_root", "nproc", "root_rw", "runtime_rw", "capabilities", "privileges", "control_plane"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temp, ExitStack() as stack:
                context, mounts = self.workspace_context(stack, Path(temp))
                for kind in ("uid", "gid"):
                    context[Path(f"/proc/self/{kind}_map")] = "0 0 4294967295\n"
                if failure == "host_init":
                    context[Path("/proc/1/status")] += "Name:\tsystemd\n"
                elif failure == "wrong_pid":
                    context[Path("/proc/self/status")] += "Pid:\t12345\n"
                elif failure == "host_proc":
                    context[Path("/proc/self/status")] += "NSpid:\t12345 42\n"
                elif failure == "init_parent":
                    context[Path("/proc/1/status")] += "PPid:\t1234\n"
                elif failure == "root_uid":
                    stack.enter_context(patch.object(runner.os, "getuid", return_value=0))
                    context[Path("/proc/self/status")] += "Uid:\t0 0 0 0\n"
                elif failure == "saved_root":
                    context[Path("/proc/self/status")] += "Uid:\t997 997 0 997\n"
                elif failure == "nproc":
                    stack.enter_context(patch.object(runner, "_workspace_nproc_enforced", return_value=False))
                elif failure == "root_rw":
                    mounts[Path("/")] = ("tmpfs", {"rw", "nosuid", "nodev"})
                elif failure == "runtime_rw":
                    mounts[runner.BINARY.resolve()] = ("ext4", {"rw"})
                elif failure == "capabilities":
                    context[Path("/proc/self/status")] += "CapEff:\t0000000000000001\n"
                elif failure == "privileges":
                    context[Path("/proc/self/status")] += "NoNewPrivs:\t0\n"
                elif failure == "control_plane":
                    exists = Path.exists
                    stack.enter_context(patch.object(Path, "exists", lambda path: path == Path("/run/systemd") or exists(path)))
                if failure:
                    with self.assertRaises(runner.InputError):
                        runner._workspace_sandbox()
                else:
                    self.assertTrue(runner._workspace_sandbox())

    def test_workspace_nproc_probe_is_bounded_and_fails_closed(self):
        for failure in (None, 1, OSError("missing interpreter"), subprocess.TimeoutExpired("probe", 3)):
            with self.subTest(failure=failure), patch.object(runner.subprocess, "run") as probe:
                if isinstance(failure, Exception):
                    probe.side_effect = failure
                else:
                    probe.return_value = SimpleNamespace(returncode=failure or 0)
                self.assertEqual(runner._workspace_nproc_enforced(), failure is None)
                args, options = probe.call_args
                self.assertEqual(args[0][1:3], ["-I", "-S"])
                self.assertEqual(options["timeout"], 3)
                self.assertEqual(options["env"], {"PATH": "/usr/bin:/bin"})

    def test_workspace_pin_mismatch_never_starts_scanner_or_systemd(self):
        with tempfile.TemporaryDirectory() as temp, ExitStack() as stack:
            root, clock, cancellation = Path(temp), FakeClock(), runner.Cancellation()
            env = self.fake_environment(stack, root, clock, workspace=True, cancellation=cancellation)
            stack.enter_context(patch.object(runner, "BINARY_SHA256", "0" * 64))
            with redirect_stdout(io.StringIO()) as output:
                self.assertEqual(runner.run(self.args("-u", "https://fixture.invalid"), cancellation), 2)
            result = json.loads(output.getvalue().splitlines()[-1])
            self.assertIn("pinned_binary_sha256_mismatch", result["blocked_reasons"])
            self.assertTrue(Path(result["manifest_file"]).is_relative_to(root / "jsapiscan"))
            env.launcher.assert_not_called()
            env.controls.assert_not_called()
            env.ownership.assert_not_called()

    def test_workspace_mountinfo_decodes_escaped_mountpoints(self):
        text = "31 30 0:5 /newroot / ro,nosuid,nodev - tmpfs tmpfs rw\n32 31 8:1 /source /work\\040space rw,nosuid,nodev - ext4 /dev/a rw\n"
        with patch.object(Path, "read_text", return_value=text):
            mounts = runner._workspace_mounts()
        self.assertEqual(mounts[Path("/")], ("tmpfs", {"ro", "nosuid", "nodev"}))
        self.assertEqual(runner._covering_mount(Path("/work space/artifacts"), mounts), Path("/work space"))

    def test_forged_workspace_marker_never_falls_back_or_creates_host_job(self):
        for cli_error in (False, True):
            with tempfile.TemporaryDirectory() as temp, ExitStack() as stack:
                root = Path(temp)
                env = self.fake_environment(stack, root, FakeClock())
                stack.enter_context(patch.dict(runner.os.environ, CSAI_WORKSPACE_SANDBOX="1"))
                stack.enter_context(patch.object(Path, "read_text", side_effect=OSError("not-proc")))
                with redirect_stdout(io.StringIO()) as output, redirect_stderr(io.StringIO()):
                    code = runner.main(["-u", "https://a.example", "-t", "wrong"]) if cli_error else runner.run(self.args("-u", "https://a.example"))
                self.assertEqual(code, 2)
                self.assertIn("untrusted_workspace_sandbox_context", json.loads(output.getvalue().splitlines()[-1])["blocked_reasons"])
                self.assertFalse((root / "runs").exists())
                env.launcher.assert_not_called()
                env.controls.assert_not_called()

    def test_workspace_success_uses_current_identity_private_artifacts_and_limits(self):
        with tempfile.TemporaryDirectory() as temp, ExitStack() as stack:
            root, clock, cancellation = Path(temp), FakeClock(), runner.Cancellation()
            def fixture(work, options):
                self.assertEqual(options["env"]["HOME"], str(work / ".home"))
                self.assertEqual(options["env"]["TMPDIR"], str(work / ".tmp"))
                self.assertEqual(options["env"]["GOMAXPROCS"], "2")
                self.assertEqual(options["umask"], 0o077)
                self.assertNotIn("CSAI_EXECUTION_ID", options["env"])
                (work / "api.csv").write_text("URL,Method\nhttps://a.example/api?token=secret-value,GET\n", encoding="utf-8")
            env = self.fake_environment(stack, root, clock, workspace=True, cancellation=cancellation, callback=fixture)
            stack.enter_context(patch.dict(runner.os.environ, CSAI_EXECUTION_ID="a3b7c901-2d4e-4f60-8a12-3456789abcde"))
            with redirect_stdout(io.StringIO()) as output:
                self.assertEqual(runner.run(self.args("-u", "https://a.example", "-header", "private-header"), cancellation), 0)
            result = json.loads(output.getvalue().splitlines()[-1])
            manifest = json.loads(Path(result["manifest_file"]).read_text("utf-8"))
            self.assertEqual(manifest["execution_mode"], "workspace")
            self.assertEqual((manifest["uid"], manifest["gid"]), (997, 997))
            self.assertTrue(manifest["complete"])
            self.assertFalse(manifest["coverage_complete"])
            self.assertTrue(manifest["candidate_only"])
            self.assertEqual(manifest["counts"]["exported"], 1)
            self.assertTrue(Path(result["manifest_file"]).is_relative_to(root / "jsapiscan"))
            self.assertFalse((root / "runs").exists())
            self.assertFalse(list(root.rglob("_input_*")))
            self.assertNotIn("private-header", str(env.commands) + output.getvalue())
            self.assertNotIn("secret-value", Path(result["candidates_file"]).read_text("utf-8"))
            command = env.commands[0]
            for flag in ("/usr/bin/prlimit", "--as=4294967296:4294967296", "--data=536870912:536870912", "--nproc=128:128", "--core=0:0", "/usr/bin/timeout", "--kill-after=2s", "300s"):
                self.assertIn(flag, command)
            env.ownership.assert_not_called()
            env.controls.assert_not_called()
            self.assertEqual(env.groups.call_count, 2)  # Cleanup also runs after a successful leader exit.
            self.assertNotIn("systemd_result", manifest["batches"][0])

    def test_workspace_timeout_cancel_and_launch_failure_stay_partial_without_systemctl(self):
        for failure in ("timeout", "watchdog", "cancel", "launch", "cleanup"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temp, ExitStack() as stack:
                root, clock, cancellation = Path(temp), FakeClock(), runner.Cancellation()
                env = self.fake_environment(stack, root, clock, duration=0 if failure == "watchdog" else 60,
                                            code=124 if failure == "watchdog" else 0, workspace=True,
                                            cancellation=cancellation, ignore_terminate=True)
                if failure == "cancel":
                    stack.enter_context(patch.object(cancellation, "wait", side_effect=lambda seconds: (clock.wait(seconds), cancellation.request(signal.SIGTERM))))
                elif failure == "launch":
                    env.launcher.side_effect = FileNotFoundError("private-helper-error")
                elif failure == "cleanup":
                    env.groups.side_effect = PermissionError("private-cleanup-error")
                with redirect_stdout(io.StringIO()) as output:
                    code = runner.run(self.args("-u", ",".join(f"https://a{i}.example" for i in range(21)), "--total-timeout", "1"), cancellation)
                self.assertEqual(code, 130 if failure == "cancel" else (1 if failure == "launch" else 124))
                manifest = json.loads(Path(json.loads(output.getvalue().splitlines()[-1])["manifest_file"]).read_text("utf-8"))
                self.assertTrue(manifest["partial"])
                self.assertFalse(manifest["complete"])
                self.assertEqual(manifest["unstarted_target_count"], 21 if failure == "launch" else 1)
                self.assertEqual(env.launcher.call_count, 1)
                self.assertFalse(list(root.rglob("_input_*")))
                self.assertNotIn("private-", output.getvalue())
                if failure not in ("launch", "cleanup"):
                    self.assertTrue(env.children[0].killed)
                if failure == "cleanup":
                    self.assertIn("process_group_signal_failed", manifest["blocked_reasons"])
                env.ownership.assert_not_called()
                env.controls.assert_not_called()

    def test_workspace_global_budget_and_execution_collision_are_preserved(self):
        with tempfile.TemporaryDirectory() as temp, ExitStack() as stack:
            root, clock, cancellation = Path(temp), FakeClock(), runner.Cancellation()
            env = self.fake_environment(stack, root, clock, duration=2, workspace=True, cancellation=cancellation)
            stack.enter_context(patch.dict(runner.os.environ, CSAI_EXECUTION_ID="a3b7c901-2d4e-4f60-8a12-3456789abcde"))
            args = self.args("-u", ",".join(f"https://a{i}.example" for i in range(21)), "--total-timeout", "10")
            with redirect_stdout(io.StringIO()):
                self.assertEqual(runner.run(args, cancellation), 0)
            self.assertIn("10s", env.commands[0])
            self.assertIn("8s", env.commands[1])
            before = env.launcher.call_count
            with redirect_stdout(io.StringIO()) as output:
                self.assertEqual(runner.run(args, cancellation), 2)
            self.assertIn("execution_directory_already_exists", output.getvalue())
            self.assertEqual(env.launcher.call_count, before)

    def test_workspace_job_paths_and_cli_errors_never_use_global_runs(self):
        with tempfile.TemporaryDirectory() as temp, ExitStack() as stack:
            root = Path(temp)
            self.workspace_context(stack, root)
            stack.enter_context(patch.object(Path, "cwd", return_value=root))
            job = runner._new_job(True)
            self.assertEqual(job.parent, root / ".jsapiscan-runs")
            for value in ("", "relative", str(root / "missing")):
                with patch.dict(runner.os.environ, CSAI_ARTIFACT_DIR=value), self.assertRaises(runner.InputError):
                    runner._new_job(True)
            stack.enter_context(patch.dict(runner.os.environ, CSAI_ARTIFACT_DIR=str(root)))
            with redirect_stdout(io.StringIO()) as output, redirect_stderr(io.StringIO()):
                self.assertEqual(runner.main(["-u", "https://a.example", "-t", "private-invalid"]), 2)
            manifest_path = Path(json.loads(output.getvalue().splitlines()[-1])["manifest_file"])
            self.assertTrue(manifest_path.is_relative_to(root / "jsapiscan"))
            self.assertEqual(json.loads(manifest_path.read_text("utf-8"))["blocked_reasons"], ["invalid_cli_input"])
            self.assertNotIn("private-invalid", output.getvalue())

    def test_execution_id_binds_normalized_directory_and_result_paths(self):
        execution_id = "a3b7c901-2d4e-4f60-8a12-3456789abcde"
        with tempfile.TemporaryDirectory() as temp, ExitStack() as stack:
            root, clock, cancellation = Path(temp), FakeClock(), runner.Cancellation()
            stack.enter_context(patch.dict(runner.os.environ, CSAI_EXECUTION_ID=execution_id.upper()))
            def fixture(work, _kwargs):
                (work / "api.csv").write_text("URL,Method\nhttps://a.example/api,GET\n", encoding="utf-8")
            self.fake_environment(stack, root, clock, cancellation=cancellation, callback=fixture)
            with redirect_stdout(io.StringIO()) as output:
                self.assertEqual(runner.run(self.args("-u", "https://a.example"), cancellation), 0)
            manifest, job = self.manifest(root)
            self.assertEqual(job.name, "execution-" + execution_id)
            self.assertEqual(manifest["execution_id"], execution_id)
            result = json.loads(output.getvalue().splitlines()[-1])
            self.assertEqual(result["execution_id"], execution_id)
            for field, relative in [("work_dir", "work"), ("manifest_file", "manifest.json"),
                                    ("stdout_file", "stdout.log"), ("candidates_file", "candidates.ndjson")]:
                self.assertEqual(Path(result[field]), job / relative)
                self.assertEqual(result[field], manifest[field])
            self.assertEqual(manifest["counts"]["exported"], 1)
            self.assertTrue((job / "work" / "batch-0001" / "api.csv").is_file())

    def test_invalid_execution_ids_fail_closed_without_fallback_or_echo(self):
        valid = "a3b7c901-2d4e-4f60-8a12-3456789abcde"
        for value in ["", valid.replace("-", ""), "{" + valid + "}", "urn:uuid:" + valid,
                      " " + valid, valid + "\n", "../private-execution", valid[:-1] + "g"]:
            with self.subTest(value=value), tempfile.TemporaryDirectory() as temp, ExitStack() as stack:
                root, clock, cancellation = Path(temp), FakeClock(), runner.Cancellation()
                stack.enter_context(patch.dict(runner.os.environ, CSAI_EXECUTION_ID=value))
                env = self.fake_environment(stack, root, clock, cancellation=cancellation)
                with redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(runner.run(self.args("-u", "https://a.example"), cancellation), 2)
                result = json.loads(output.getvalue().splitlines()[-1])
                self.assertEqual(result["blocked_reasons"], ["invalid_execution_id"])
                self.assertIsNone(result["manifest_file"])
                self.assertFalse((root / "runs").exists())
                self.assertNotIn("private-execution", output.getvalue())
                env.launcher.assert_not_called()
                env.controls.assert_not_called()

    def test_existing_execution_directory_or_file_is_never_reused(self):
        execution_id = "a3b7c901-2d4e-4f60-8a12-3456789abcde"
        for directory in (True, False):
            with self.subTest(directory=directory), tempfile.TemporaryDirectory() as temp, ExitStack() as stack:
                root, clock, cancellation = Path(temp), FakeClock(), runner.Cancellation()
                stack.enter_context(patch.dict(runner.os.environ, CSAI_EXECUTION_ID=execution_id))
                env = self.fake_environment(stack, root, clock, cancellation=cancellation)
                job = root / "runs" / ("execution-" + execution_id)
                job.parent.mkdir()
                if directory:
                    job.mkdir()
                    marker = job / "manifest.json"
                else:
                    marker = job
                marker.write_bytes(b"existing private data")
                with redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(runner.run(self.args("-u", "https://a.example"), cancellation), 2)
                result = json.loads(output.getvalue().splitlines()[-1])
                self.assertEqual(result["blocked_reasons"], ["execution_directory_already_exists"])
                self.assertIsNone(result["manifest_file"])
                self.assertEqual(marker.read_bytes(), b"existing private data")
                self.assertEqual(list(job.parent.iterdir()), [job])
                env.launcher.assert_not_called()
                env.controls.assert_not_called()

    def test_no_execution_environment_retains_unique_legacy_directories(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(runner, "RUN_ROOT", Path(temp) / "runs"):
            first, second = runner._new_job(), runner._new_job()
            self.assertTrue(first.name.startswith("run-"))
            self.assertTrue(second.name.startswith("run-"))
            self.assertNotEqual(first, second)

    def test_cli_error_with_invalid_or_existing_execution_id_is_safe(self):
        execution_id = "a3b7c901-2d4e-4f60-8a12-3456789abcde"
        for value, reason in [("private-invalid-id", "invalid_execution_id"),
                              (execution_id, "execution_directory_already_exists")]:
            with self.subTest(reason=reason), tempfile.TemporaryDirectory() as temp, ExitStack() as stack:
                root, clock = Path(temp), FakeClock()
                env = self.fake_environment(stack, root, clock)
                stack.enter_context(patch.dict(runner.os.environ, CSAI_EXECUTION_ID=value))
                job = root / "runs" / ("execution-" + execution_id)
                job.mkdir(parents=True)
                with redirect_stdout(io.StringIO()) as output, redirect_stderr(io.StringIO()):
                    self.assertEqual(runner.main(["-u", "https://a.example", "-t", "invalid"]), 2)
                result = json.loads(output.getvalue().splitlines()[-1])
                self.assertEqual(result["blocked_reasons"], ["invalid_cli_input", reason])
                self.assertIsNone(result["manifest_file"])
                self.assertEqual(list(job.parent.iterdir()), [job])
                self.assertFalse(list(job.iterdir()))
                self.assertNotIn("private-invalid-id", output.getvalue())
                env.launcher.assert_not_called()

    def test_default_mapping_remains_bounded_get_only_and_pinned(self):
        args = self.args("-u", "https://app.example.test", "-savejs", "-tlsverify")
        command = runner.build_upstream_args(args, runner.prepare_targets(args))
        for flag, value in [("-t", "1"), ("-ft", "2"), ("-d", "8"), ("-time", "8"), ("-maxreq", "1000"), ("-maxhtml", "40"), ("-maxapi", "200"), ("-o", "txt"), ("-op", "scan.txt")]:
            self.assertEqual(command[command.index(flag) + 1], value)
        for flag in ("-aget", "-savejs", "-tlsverify"):
            self.assertIn(flag, command)
        for flag in ("-api", "-Ineedparms", "-gorog", "-extlink"):
            self.assertNotIn(flag, command)
        self.assertEqual(runner.BINARY_SHA256, "bf829b3e754a98c2817b5aa73dd138cf63a761dec669b1227e24a7f316958b68")

    def test_selection_and_integer_limits_reject_bad_input(self):
        for values in [[], ["-u", "https://a.example", "-f", "targets.txt"]]:
            with self.subTest(values=values), self.assertRaises(SystemExit):
                self.args(*values)
        for flag, value in [("-maxapi", "0"), ("-maxreq", "-1"), ("-ft", "11"), ("-t", "6"), ("--total-timeout", "1801"), ("--batch-size", "21"), ("--heartbeat-interval", "14"), ("--heartbeat-interval", "31"), ("--export-timeout", "301"), ("-t", "[1]")]:
            with self.subTest(flag=flag), self.assertRaises(SystemExit):
                self.args("-u", "https://app.example", flag, value)

    def test_input_types_and_urls_are_checked_before_execution(self):
        for url in ["file:///etc/passwd", "javascript:alert(1)", "https://user:pass@app.example", "https://app.example/\nsecret", "https://app.example/a b", "https://app.example:invalid", "https://app.example:0"]:
            with self.subTest(url=url), self.assertRaises(ValueError):
                runner.prepare_targets(self.args("-u", url))
        for field, value in [("url", ["https://a.example"]), ("threads", True), ("api_tests", "false"), ("targets_file", {})]:
            args = self.args("-u", "https://app.example")
            setattr(args, field, value)
            with self.subTest(field=field), self.assertRaises(runner.InputError):
                runner.prepare_targets(args)

    def test_target_file_is_deduplicated_and_larger_lists_stay_bounded(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "targets.txt"
            path.write_text("# authorized URLs\nhttps://a.example\nhttps://a.example\nhttps://b.example\n", encoding="utf-8")
            args = self.args("-f", str(path))
            self.assertEqual(runner.prepare_targets(args), ["https://a.example", "https://b.example"])
            path.write_text("\n".join(f"https://target{i}.example" for i in range(21)), encoding="utf-8")
            self.assertEqual(len(runner.prepare_targets(args)), 21)
            path.write_text("\n".join(f"https://target{i}.example" for i in range(201)), encoding="utf-8")
            with self.assertRaises(ValueError):
                runner.prepare_targets(args)
            path.write_bytes(b"a" * (runner.MAX_INPUT_BYTES + 1))
            with self.assertRaises(ValueError):
                runner.read_input(path)
            for file in (Path(temp), Path(temp) / "missing"):
                with self.assertRaises(ValueError):
                    runner.read_input(file)
            path.write_bytes(b"bad\x00file")
            with self.assertRaises(ValueError):
                runner.read_input(path)

    def test_post_fallback_remains_explicit_and_proxy_dependencies_preserved(self):
        for values in [("--allow-post-retry",), ("-api", "-aget", "--allow-post-retry"), ("-pa",)]:
            with self.subTest(values=values), self.assertRaises(ValueError):
                runner.prepare_targets(self.args("-u", "https://a.example", *values))
        args = self.args("-u", "https://a.example", "-api", "--allow-post-retry")
        self.assertNotIn("-aget", runner.build_upstream_args(args, runner.prepare_targets(args)))
        args = self.args("-u", "https://a.example", "-api")
        self.assertIn("-aget", runner.build_upstream_args(args, runner.prepare_targets(args)))

    def test_output_filename_and_sandbox_properties_are_not_relaxed(self):
        for name in ["../config.yaml", "/etc/cron.d/task", "folder/report.txt", "bad name.txt", ".hidden"]:
            with self.subTest(name=name), self.assertRaises(ValueError):
                runner.prepare_targets(self.args("-u", "https://a.example", "-op", name))
        command = runner.sandbox_command(Path("/opt/jsapiscan/bin"), ["-u", "https://a.example"], Path("/private/work"), "test-unit", 300)
        for value in ["User=csai-jsapiscan", "NoNewPrivileges=yes", "ProtectSystem=strict", "ProtectHome=yes", "RuntimeMaxSec=300", "MemoryMax=512M", "CapabilityBoundingSet=", "KillMode=control-group", "TimeoutStopSec=5s"]:
            self.assertIn(value, command)
        self.assertTrue(any("InaccessiblePaths=" in value and "/opt/CyberStrikeAI-U" in value for value in command))

    def test_supported_flags_and_secret_file_mapping(self):
        args = self.args("-u", "https://a.example", "-api", "-pa", "-p", "http://127.0.0.1:8080", "-gjca", "secret,key", "-sc", "404,429", "-person", "-ey", "-scan-libs", "-wl", "-baseapipath", "/v1", "-header", "Authorization: sensitive-fixture")
        command = runner.build_upstream_args(args, runner.prepare_targets(args), headers_path=Path("/private/headers.txt"))
        for flag in ["-api", "-pa", "-person", "-ey", "-scan-libs", "-wl", "-header-file"]:
            self.assertIn(flag, command)
        self.assertNotIn("-header", command)
        self.assertNotIn("sensitive-fixture", str(command))

    def test_silent_child_emits_20_second_heartbeats_without_sensitive_data(self):
        with tempfile.TemporaryDirectory() as temp, ExitStack() as stack:
            root, clock, cancellation = Path(temp), FakeClock(), runner.Cancellation()
            env = self.fake_environment(stack, root, clock, duration=51, cancellation=cancellation)
            output = io.StringIO()
            args = self.args("-u", "https://app.example/path?token=sensitive-target", "-header", "Authorization: sensitive-header")
            with redirect_stdout(output):
                self.assertEqual(runner.run(args, cancellation), 0)
            messages = [json.loads(line) for line in output.getvalue().splitlines()]
            scans = [item for item in messages if item.get("phase") == "scan"]
            self.assertEqual([item["elapsed_seconds"] for item in scans], [0, 20, 40])
            self.assertNotIn("sensitive-target", output.getvalue())
            self.assertNotIn("sensitive-header", output.getvalue())
            self.assertNotIn("app.example", output.getvalue())
            self.assertNotIn("sensitive-target", str(env.commands))
            self.assertNotIn("sensitive-header", str(env.commands))
            manifest, _job = self.manifest(root)
            self.assertTrue(manifest["complete"])
            self.assertFalse(manifest["coverage_complete"])

    def test_twenty_one_targets_are_two_batches_and_global_budget_is_not_reset(self):
        with tempfile.TemporaryDirectory() as temp, ExitStack() as stack:
            root, clock, cancellation = Path(temp), FakeClock(), runner.Cancellation()
            env = self.fake_environment(stack, root, clock, duration=2, cancellation=cancellation)
            targets = [f"https://target{i}.example" for i in range(21)]
            args = self.args("-u", ",".join(targets), "--total-timeout", "10", "--batch-timeout", "300")
            with redirect_stdout(io.StringIO()):
                self.assertEqual(runner.run(args, cancellation), 0)
            self.assertEqual([len(batch) for batch in env.batches], [20, 1])
            self.assertEqual(sum(env.batches, []), targets)
            self.assertIn("RuntimeMaxSec=10", env.commands[0])
            self.assertIn("RuntimeMaxSec=8", env.commands[1])
            for command in env.commands:
                self.assertEqual(command[command.index("-maxreq") + 1], "1000")
                self.assertIn("-aget", command)
            manifest, _job = self.manifest(root)
            self.assertEqual(manifest["started_target_count"], 21)
            self.assertTrue(manifest["scan_complete"])

    def test_global_timeout_stops_without_retries_and_leaves_manifest(self):
        with tempfile.TemporaryDirectory() as temp, ExitStack() as stack:
            root, clock, cancellation = Path(temp), FakeClock(), runner.Cancellation()
            env = self.fake_environment(stack, root, clock, duration=60, cancellation=cancellation, ignore_terminate=True)
            args = self.args("-u", ",".join(f"https://a{i}.example" for i in range(21)), "--total-timeout", "1")
            with redirect_stdout(io.StringIO()):
                self.assertEqual(runner.run(args, cancellation), 124)
            manifest, job = self.manifest(root)
            self.assertTrue(manifest["timed_out"])
            self.assertTrue(manifest["partial"])
            self.assertEqual(manifest["unstarted_target_count"], 1)
            self.assertEqual(env.launcher.call_count, 1)
            self.assertTrue(env.children[0].terminated)
            self.assertTrue(env.children[0].killed)
            self.assertIn("stop", [command[1] for command in env.control_calls])
            self.assertFalse(list((job / "work").rglob("_input_*")))

    def test_cancel_signal_sets_state_without_raising_and_finalizes_manifest(self):
        with tempfile.TemporaryDirectory() as temp, ExitStack() as stack:
            root, clock, cancellation = Path(temp), FakeClock(), runner.Cancellation()
            env = self.fake_environment(stack, root, clock, duration=60, cancellation=cancellation)
            headers = root / "original-headers.txt"
            headers.write_text("Authorization: private-fixture\n", encoding="utf-8")
            def cancel_wait(seconds):
                clock.wait(seconds)
                cancellation.request(signal.SIGTERM, None)
                cancellation.request(signal.SIGTERM, None)
            stack.enter_context(patch.object(cancellation, "wait", side_effect=cancel_wait))
            with redirect_stdout(io.StringIO()):
                code = runner.run(self.args("-u", "https://a.example", "-header-file", str(headers)), cancellation)
            self.assertEqual(code, 130)
            manifest, job = self.manifest(root)
            self.assertEqual(manifest["state"], "cancelled")
            self.assertTrue(manifest["cancelled"])
            self.assertFalse(manifest["complete"])
            self.assertFalse(manifest["export_complete"])
            self.assertTrue(env.children[0].terminated)
            self.assertFalse(list((job / "work").rglob("_input_*")))
            self.assertEqual(headers.read_text("utf-8"), "Authorization: private-fixture\n")

    def test_systemd_timeout_and_launch_exception_are_durable(self):
        for launch_error in (False, True):
            with self.subTest(launch_error=launch_error), tempfile.TemporaryDirectory() as temp, ExitStack() as stack:
                root, clock, cancellation = Path(temp), FakeClock(), runner.Cancellation()
                env = self.fake_environment(stack, root, clock, code=143, result="timeout", cancellation=cancellation)
                if launch_error:
                    env.launcher.side_effect = OSError("private-target-and-header-in-error")
                output = io.StringIO()
                with redirect_stdout(output):
                    self.assertEqual(runner.run(self.args("-u", "https://a.example"), cancellation), 124)
                manifest, job = self.manifest(root)
                self.assertTrue(manifest["timed_out"])
                self.assertEqual(manifest["batches"][0]["systemd_result"], "timeout")
                self.assertIn("reset-failed", [command[1] for command in env.control_calls])
                self.assertFalse(list((job / "work").rglob("_input_*")))
                self.assertNotIn("private-target-and-header", output.getvalue())

    def test_failed_systemd_stop_still_kills_launcher_and_writes_manifest(self):
        with tempfile.TemporaryDirectory() as temp, ExitStack() as stack:
            root, clock, cancellation = Path(temp), FakeClock(), runner.Cancellation()
            env = self.fake_environment(stack, root, clock, duration=60, cancellation=cancellation)
            def controls(command, **kwargs):
                env.control_calls.append(command)
                if command[1] == "stop":
                    raise subprocess.TimeoutExpired("systemctl", kwargs["timeout"])
                return SimpleNamespace(returncode=0, stdout="success")
            env.controls.side_effect = controls
            with redirect_stdout(io.StringIO()):
                self.assertEqual(runner.run(self.args("-u", "https://a.example", "--total-timeout", "1"), cancellation), 124)
            manifest, _job = self.manifest(root)
            self.assertIn("systemd_stop_failed", manifest["blocked_reasons"])
            self.assertIn("kill", [command[1] for command in env.control_calls])
            self.assertTrue(env.children[0].terminated)

    def test_bad_input_or_binary_blocks_before_any_child(self):
        for failure in ("file", "type", "sha", "root_user"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temp, ExitStack() as stack:
                root, clock, cancellation = Path(temp), FakeClock(), runner.Cancellation()
                env = self.fake_environment(stack, root, clock, cancellation=cancellation)
                args = self.args("-u", "https://a.example")
                if failure == "file":
                    args.headers_file = str(root / "missing-headers")
                elif failure == "type":
                    args.url = ["https://private.example"]
                elif failure == "sha":
                    stack.enter_context(patch.object(runner, "BINARY_SHA256", "0" * 64))
                else:
                    env.account.pw_uid = 0
                with redirect_stdout(io.StringIO()):
                    self.assertEqual(runner.run(args, cancellation), 2)
                manifest, _job = self.manifest(root)
                self.assertTrue(manifest["blocked_reasons"])
                env.launcher.assert_not_called()
                env.controls.assert_not_called()

    def test_cli_type_error_is_sanitized_and_has_manifest(self):
        with tempfile.TemporaryDirectory() as temp, ExitStack() as stack:
            root, clock, cancellation = Path(temp), FakeClock(), runner.Cancellation()
            env = self.fake_environment(stack, root, clock, cancellation=cancellation)
            output, error = io.StringIO(), io.StringIO()
            with redirect_stdout(output), redirect_stderr(error):
                self.assertEqual(runner.main(["-u", "https://a.example", "-t", "private-invalid-value"]), 2)
            manifest, _job = self.manifest(root)
            self.assertEqual(manifest["blocked_reasons"], ["invalid_cli_input"])
            self.assertNotIn("private-invalid-value", output.getvalue() + error.getvalue())
            env.launcher.assert_not_called()

    def test_offline_validation_does_not_need_linux_or_systemd(self):
        with patch.object(runner.subprocess, "Popen") as child, patch.object(runner.subprocess, "run") as controls, redirect_stdout(io.StringIO()) as output:
            self.assertEqual(runner.run(self.args("-u", "https://a.example", "--validate-only")), 0)
        child.assert_not_called()
        controls.assert_not_called()
        self.assertEqual(json.loads(output.getvalue().splitlines()[-1])["network_requests"], 0)

    def test_export_exception_and_broken_outer_stdout_do_not_lose_manifest(self):
        with tempfile.TemporaryDirectory() as temp, ExitStack() as stack:
            root, clock, cancellation = Path(temp), FakeClock(), runner.Cancellation()
            self.fake_environment(stack, root, clock, cancellation=cancellation)
            stack.enter_context(patch.object(runner, "collect_artifacts", side_effect=RuntimeError("private-error")))
            stack.enter_context(patch("builtins.print", side_effect=BrokenPipeError()))
            self.assertEqual(runner.run(self.args("-u", "https://a.example"), cancellation), 1)
            manifest, _job = self.manifest(root)
            self.assertIn("artifact_export_exception", manifest["blocked_reasons"])
            self.assertFalse(manifest["export_complete"])

    def test_large_csv_exports_all_rows_with_bounded_preview_and_streamed_hashes(self):
        with tempfile.TemporaryDirectory() as temp:
            work = Path(temp) / "work"
            work.mkdir()
            path = work / "api.csv"
            with path.open("w", encoding="utf-8", newline="") as stream:
                writer = csv.writer(stream)
                writer.writerow(["URL", "Method", "Length", "Body", "Status", "Headers"])
                for index in range(10051):
                    writer.writerow([f"https://a.example/api/item{index}?token=private-token", "GET", "900", "private-body" + "x" * 900, "200", "private-header"])
                writer.writerow(["https://a.example/api/item0?token=another-token", "GET", "900", "body", "200", "header"])
            self.assertGreater(path.stat().st_size, 8 * 1024 * 1024)
            with patch.object(Path, "read_bytes", side_effect=AssertionError("whole-file reads forbidden")):
                result = runner.collect_artifacts(work, Path(temp) / "candidates.ndjson")
            self.assertTrue(result["export_complete"])
            self.assertTrue(result["raw_complete"])
            self.assertEqual(result["counts"], {"raw": 10052, "unique": 10051, "exported": 10051, "skipped": 1, "parse_errors": 0, "duplicates": 1})
            self.assertEqual(len(result["candidates_preview"]), 50)
            with Path(result["candidates_file"]).open(encoding="utf-8") as stream:
                count = 0
                for line in stream:
                    count += 1
                    self.assertNotIn("private-token", line)
                    self.assertNotIn("private-body", line)
                    self.assertNotIn("private-header", line)
                self.assertEqual(count, 10051)
            self.assertIn("sha256", result["artifacts"][0])
            self.assertFalse(list(Path(temp).glob("candidate-index-*")))

    def test_csv_field_limit_and_truncation_never_claim_completeness(self):
        for body, field_limit, expected_rows in [("x" * 200, 64, 0), ('"unterminated', 1024, 1)]:
            with self.subTest(field_limit=field_limit), tempfile.TemporaryDirectory() as temp:
                work = Path(temp) / "work"
                work.mkdir()
                prefix = "URL,Method,Body\n" + ("https://a.example/ok,GET,ok\n" if expected_rows else "")
                (work / "api.csv").write_text(prefix + "https://a.example/bad,GET," + body, encoding="utf-8")
                with patch.object(inventory, "MAX_CSV_FIELD_CHARS", field_limit):
                    result = runner.collect_artifacts(work)
                self.assertFalse(result["export_complete"])
                self.assertFalse(result["raw_complete"])
                self.assertEqual(result["counts"]["raw"], expected_rows)
                self.assertEqual(result["counts"]["exported"], expected_rows)
                self.assertGreater(result["counts"]["parse_errors"], 0)

    def test_multiline_logical_csv_record_limit_is_not_hidden_by_line_limits(self):
        with tempfile.TemporaryDirectory() as temp:
            work = Path(temp) / "work"
            work.mkdir()
            (work / "api.csv").write_text('URL,Method,Body\nhttps://a.example/api,GET,"' + ("x" * 50 + "\n") * 3 + '"\n', encoding="utf-8")
            with patch.object(inventory, "MAX_CSV_RECORD_CHARS", 128):
                result = runner.collect_artifacts(work)
            self.assertFalse(result["export_complete"])
            self.assertFalse(result["raw_complete"])
            self.assertEqual(result["counts"]["raw"], 0)
            self.assertEqual(result["csv_files"][0]["blocked_reason"], "csv_record_limit")

    def test_bad_csv_shape_and_method_have_truthful_counts(self):
        with tempfile.TemporaryDirectory() as temp:
            work = Path(temp) / "work"
            work.mkdir()
            (work / "api.csv").write_text("URL,Method\nhttps://a.example/a,GET\nhttps://a.example/b,\nhttps://a.example/c,GET,extra\n", encoding="utf-8")
            result = runner.collect_artifacts(work)
            self.assertTrue(result["raw_complete"])
            self.assertFalse(result["export_complete"])
            self.assertEqual(result["counts"]["raw"], 3)
            self.assertEqual(result["counts"]["exported"], 1)
            self.assertEqual(result["counts"]["skipped"], 2)
            self.assertEqual(result["counts"]["parse_errors"], 2)

    def test_export_timeout_preserves_partial_file_and_exact_observed_count(self):
        with tempfile.TemporaryDirectory() as temp:
            work = Path(temp) / "work"
            work.mkdir()
            (work / "api.csv").write_text("URL,Method\n" + "\n".join(f"https://a.example/item{i},GET" for i in range(10)), encoding="utf-8")
            with patch.object(inventory.time, "monotonic", return_value=10):
                result = runner.collect_artifacts(work, deadline=9)
            self.assertEqual(result["counts"]["raw"], 0)
            self.assertFalse(result["raw_complete"])
            self.assertFalse(result["export_complete"])
            self.assertIn("export_timeout", result["blockers"])
            self.assertTrue(Path(result["candidates_file"]).exists())

    def test_cancel_during_export_keeps_observed_rows_and_final_cancelled_state(self):
        with tempfile.TemporaryDirectory() as temp, ExitStack() as stack:
            root, clock, cancellation = Path(temp), FakeClock(), runner.Cancellation()
            def fixture(work, _kwargs):
                (work / "api.csv").write_text("URL,Method\n" + "\n".join(f"https://a.example/item{i},GET" for i in range(10)), encoding="utf-8")
            self.fake_environment(stack, root, clock, cancellation=cancellation, callback=fixture)
            original_tick = runner.Heartbeat.tick
            def tick(heartbeat, *values, **counts):
                original_tick(heartbeat, *values, **counts)
                if counts.get("exported") == 3:
                    cancellation.request(signal.SIGTERM)
            stack.enter_context(patch.object(runner.Heartbeat, "tick", new=tick))
            with redirect_stdout(io.StringIO()):
                self.assertEqual(runner.run(self.args("-u", "https://a.example"), cancellation), 130)
            manifest, _job = self.manifest(root)
            self.assertEqual(manifest["state"], "cancelled")
            self.assertFalse(manifest["export_complete"])
            self.assertFalse(manifest["raw_complete"])
            self.assertEqual(manifest["counts"]["raw"], 3)
            self.assertEqual(manifest["counts"]["exported"], 3)
            with Path(manifest["candidates_file"]).open(encoding="utf-8") as stream:
                self.assertEqual(sum(1 for _line in stream), 3)

    def test_missing_systemd_still_cleans_launcher_and_reports_runtime_bound(self):
        with tempfile.TemporaryDirectory() as temp, ExitStack() as stack:
            root, clock, cancellation = Path(temp), FakeClock(), runner.Cancellation()
            env = self.fake_environment(stack, root, clock, duration=60, cancellation=cancellation)
            env.controls.side_effect = OSError("control_plane_unavailable")
            with redirect_stdout(io.StringIO()):
                self.assertEqual(runner.run(self.args("-u", "https://a.example", "--total-timeout", "1"), cancellation), 124)
            manifest, _job = self.manifest(root)
            self.assertIn("systemd_kill_failed", manifest["blocked_reasons"])
            self.assertTrue(env.children[0].terminated)
            self.assertIn("RuntimeMaxSec=1", env.commands[0])
            self.assertFalse(manifest["complete"])

    def test_nonzero_exit_has_explicit_reason_and_is_never_retried(self):
        with tempfile.TemporaryDirectory() as temp, ExitStack() as stack:
            root, clock, cancellation = Path(temp), FakeClock(), runner.Cancellation()
            env = self.fake_environment(stack, root, clock, code=-9, result="oom-kill", cancellation=cancellation)
            with redirect_stdout(io.StringIO()):
                self.assertEqual(runner.run(self.args("-u", "https://a.example"), cancellation), 137)
            manifest, _job = self.manifest(root)
            self.assertIn("systemd_oom-kill", manifest["blocked_reasons"])
            self.assertIn("upstream_nonzero_exit", manifest["blocked_reasons"])
            self.assertEqual(env.launcher.call_count, 1)

    def test_recipe_flags_and_new_parameter_defaults_match_parser(self):
        import re
        root = Path(__file__).resolve().parents[1]
        text = (root / "tools" / "jsapiscan.yaml").read_text(encoding="utf-8")
        parser = runner.make_parser()
        flags = {flag for action in parser._actions for flag in action.option_strings}
        for flag in re.findall(r'''^\s+flag: ["']?([^\s"']+)["']?\s*$''', text, re.M):
            self.assertIn(flag, flags)
        # Server-side YAML serializers may omit quotes around scalar names.
        sections = re.split(r'''(?m)^\s*- name: ["']?([\w-]+)["']?\s*$''', text)
        parameters = dict(zip(sections[1::2], sections[2::2]))
        args = self.args("-u", "https://a.example")
        for name, dest in [("batch_size", "batch_size"), ("batch_timeout_seconds", "batch_timeout"), ("heartbeat_interval_seconds", "heartbeat_interval"), ("export_timeout_seconds", "export_timeout")]:
            self.assertIn(name, parameters)
            self.assertEqual(int(re.search(r"    default: (\d+)", parameters[name]).group(1)), getattr(args, dest))
        self.assertIn("最多200", text)
        self.assertIn("coverage_complete", text)

    def test_artifact_symlinks_never_read_outside_work(self):
        with tempfile.TemporaryDirectory() as temp:
            root, work = Path(temp), Path(temp) / "work"
            work.mkdir()
            outside = root / "outside.csv"
            outside.write_text("URL,Method\nhttps://outside.example,GET\n", encoding="utf-8")
            try:
                (work / "linked.csv").symlink_to(outside)
            except OSError:
                self.skipTest("symlink privileges unavailable")
            result = runner.collect_artifacts(work)
            self.assertEqual(result["artifacts"], [])
            self.assertEqual(result["counts"]["exported"], 0)


@unittest.skipUnless(sys.platform == "linux" and os.environ.get("CSAI_JSAPISCAN_BWRAP_TEST") == "1",
                     "opt-in Linux bubblewrap fixture; no network or scanner binary")
class WorkspaceSandboxIntegrationTests(unittest.TestCase):
    def test_real_namespace_limits_timeout_and_cancellation_offline(self):
        self.assertIsNotNone(shutil.which("bwrap"))
        with tempfile.TemporaryDirectory(prefix="jsapiscan-fixture-") as temp:
            root = Path(temp)
            root.chmod(0o755)
            runtime = root / "runtime"
            runtime.mkdir(mode=0o755)
            runtime.chmod(0o755)
            for module in (runner, inventory):
                copied = runtime / Path(module.__file__).name
                shutil.copyfile(module.__file__, copied)
                copied.chmod(0o644)
            uid, gid = (65534, 65534) if os.geteuid() == 0 else (os.getuid(), os.getgid())
            prefix = ["/usr/bin/setpriv", f"--reuid={uid}", f"--regid={gid}", "--clear-groups"] if os.geteuid() == 0 else []
            modes = ("success", "timeout", "cancel", "root_mapping", "host_nonroot") if os.geteuid() == 0 else ("success", "timeout", "cancel")
            for mode in modes:
                with self.subTest(mode=mode):
                    work, artifacts = root / (mode + "-work"), root / (mode + "-artifacts")
                    for directory in (work, artifacts):
                        directory.mkdir(mode=0o700)
                        if os.geteuid() == 0:
                            os.chown(directory, 0 if mode == "root_mapping" else uid, 0 if mode == "root_mapping" else gid)
                    fixture = runtime / "fixture.py"
                    fixture.write_text("#!/usr/bin/python3\n" +
                        "import errno, json, os, resource, signal, time\nfrom pathlib import Path\n" +
                        "Path('api.csv').write_text('URL,Method\\nhttps://fixture.invalid/api?token=secret,GET\\nhttps://fixture.invalid/api?token=duplicate,GET\\n')\n" +
                        f"mode = {('success' if mode == 'host_nonroot' else mode)!r}\n" +
                        "limits = {name: resource.getrlimit(getattr(resource, 'RLIMIT_' + name)) for name in ('AS', 'DATA', 'NPROC', 'CPU', 'CORE', 'NOFILE')}\n" +
                        "Path('limits.json').write_text(json.dumps(limits))\n" +
                        "if mode != 'success':\n signal.signal(signal.SIGTERM, signal.SIG_IGN)\n pid = os.fork()\n Path('pid-' + str(os.getpid())).write_text(str(os.getpgrp()))\n time.sleep(30)\n os._exit(1)\n" +
                        "try:\n bytearray(600 * 1024 * 1024)\n raise AssertionError('memory limit ineffective')\nexcept MemoryError:\n pass\n" +
                        "resource.setrlimit(resource.RLIMIT_NPROC, (0, 0))\n" +
                        "try:\n pid = os.fork()\nexcept OSError as exc:\n assert exc.errno == errno.EAGAIN\nelse:\n" +
                        " if pid == 0: os._exit(1)\n os.waitpid(pid, 0)\n raise AssertionError('NPROC ineffective')\n" +
                        "Path('limits-enforced').write_text('ok')\n", encoding="utf-8")
                    fixture.chmod(0o755)
                    driver = runtime / "driver.py"
                    driver.write_text("import hashlib, os, signal, sys, threading\nfrom pathlib import Path\n" +
                        "sys.path.insert(0, '/runtime')\nimport jsapiscan_runner as runner\n" +
                        "runner.BINARY = Path('/runtime/fixture.py')\nrunner.BINARY_SHA256 = hashlib.sha256(runner.BINARY.read_bytes()).hexdigest()\n" +
                        ("threading.Timer(0.8, lambda: os.kill(os.getpid(), signal.SIGTERM)).start()\n" if mode == "cancel" else "") +
                        "sys.exit(runner.main(sys.argv[1:]))\n", encoding="utf-8")
                    driver.chmod(0o644)
                    command = ([] if mode in ("root_mapping", "host_nonroot") else prefix) + ["/usr/bin/bwrap", "--die-with-parent", "--new-session", "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--unshare-net", "--cap-drop", "ALL", "--clearenv"]
                    if mode != "host_nonroot":
                        command += ["--unshare-user"]
                    if mode in ("root_mapping", "host_nonroot"):
                        command += ["--uid", str(uid), "--gid", str(gid)]
                    for path in ("/usr", "/lib", "/lib64", "/bin"):
                        if Path(path).exists():
                            command += ["--ro-bind", path, path]
                    command += ["--proc", "/proc", "--dev", "/dev", "--ro-bind", str(runtime), "/runtime",
                                "--bind", str(work), "/workspace", "--bind", str(artifacts), "/artifacts",
                                "--setenv", "CSAI_WORKSPACE_SANDBOX", "1", "--setenv", "CSAI_ARTIFACT_DIR", "/artifacts",
                                "--setenv", "CSAI_EXECUTION_ID", "a3b7c901-2d4e-4f60-8a12-3456789abcde",
                                "--remount-ro", "/", "--chdir", "/workspace", "--", "/usr/bin/python3", "-I", "/runtime/driver.py",
                                "-u", "https://fixture.invalid", "--total-timeout", "15", "--batch-timeout", "1" if mode == "timeout" else "10"]
                    result = subprocess.run(command, capture_output=True, text=True, timeout=20, check=False)
                    if mode == "host_nonroot" and result.returncode != 0 and "Specifying --uid requires --unshare-user or --userns" in result.stderr:
                        self.assertFalse(list(artifacts.iterdir()))
                        self.skipTest("installed bwrap rejects --uid without a user namespace; no fallback attempted")
                    self.assertEqual(result.returncode, {"success": 0, "timeout": 124, "cancel": 130, "root_mapping": 2, "host_nonroot": 0}[mode], result.stdout + result.stderr)
                    manifests = list(artifacts.rglob("manifest.json"))
                    if mode == "root_mapping":
                        self.assertEqual(manifests, [])
                        self.assertIn("workspace_resource_limits_require_nonroot_uid_mapping", result.stdout)
                        self.assertFalse(list(artifacts.iterdir()))
                        continue
                    self.assertEqual(len(manifests), 1, result.stdout + result.stderr)
                    manifest = json.loads(manifests[0].read_text("utf-8"))
                    self.assertEqual(manifest["uid"], uid)
                    self.assertEqual(manifest["execution_mode"], "workspace")
                    self.assertEqual(manifest["batches"][0]["process_group_result"], "stopped")
                    self.assertNotIn("systemd_result", manifest["batches"][0])
                    self.assertTrue(manifest["candidate_only"])
                    self.assertFalse(manifest["coverage_complete"])
                    self.assertFalse(list(artifacts.rglob("_input_*")))
                    self.assertNotIn("secret", result.stdout)
                    self.assertEqual(manifest["complete"], mode in ("success", "host_nonroot"))
                    if mode in ("success", "host_nonroot"):
                        self.assertEqual(manifest["counts"]["raw"], 2)
                        self.assertEqual(manifest["counts"]["exported"], 1)
                        self.assertEqual(next(artifacts.rglob("limits-enforced")).read_text("utf-8"), "ok")
                        limits = json.loads(next(artifacts.rglob("limits.json")).read_text("utf-8"))
                        self.assertEqual(limits["NPROC"], [128, 128])
                        self.assertEqual(limits["DATA"], [512 * 1024 ** 2] * 2)
                        self.assertEqual(limits["AS"], [4 * 1024 ** 3] * 2)
                    elif mode == "timeout":
                        self.assertTrue(manifest["timed_out"])
                    else:
                        self.assertEqual(manifest["state"], "cancelled")
                        self.assertFalse(manifest["export_complete"])


if __name__ == "__main__":
    unittest.main()
