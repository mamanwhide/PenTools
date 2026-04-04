"""
ToolRunner — universal subprocess wrapper for executing pentest tools.

Security guarantees:
  - NEVER uses shell=True (prevents shell injection)
  - All arguments passed as list (not concatenated strings)
  - Output is size-capped to prevent log flooding
  - Timeout is strictly enforced
  - Sensitive params are masked before any logging
"""
from __future__ import annotations
import os
import re
import shutil
import subprocess
import threading
from pathlib import Path
from typing import Callable

from django.conf import settings


MAX_OUTPUT_BYTES = 10 * 1024 * 1024   # 10 MB hard cap on captured output
TOOLS_BIN_DIR = getattr(settings, "TOOLS_BIN_DIR", "/opt/tools/bin")
SCAN_OUTPUT_DIR = getattr(settings, "SCAN_OUTPUT_DIR", "/tmp/pentools")


class ToolNotFoundError(Exception):
    pass


class ToolRunner:
    """
    Run a pentest binary and capture / stream its output.

    Example usage:
        runner = ToolRunner("nmap")
        result = runner.run(
            args=["-sV", "-p", "80,443", "example.com"],
            timeout=300,
            stream=lambda lvl, msg: channel_send(lvl, msg),
        )
    """

    def __init__(self, tool_name: str):
        self.tool_name = tool_name
        self.tool_path = self._resolve_tool(tool_name)

    def _resolve_tool(self, name: str) -> str:
        # Check tools volume first, then system PATH
        candidate = os.path.join(TOOLS_BIN_DIR, name)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
        system_path = shutil.which(name)
        if system_path:
            return system_path
        raise ToolNotFoundError(
            f"Tool '{name}' not found in {TOOLS_BIN_DIR} or system PATH."
        )

    def run(
        self,
        args: list[str],
        timeout: int = 3600,
        cwd: str | None = None,
        env_extra: dict | None = None,
        stream: Callable[[str, str], None] | None = None,
        mask_patterns: list[str] | None = None,
    ) -> dict:
        """
        Execute the tool and return result dict.

        Args:
            args:           Command arguments (list — NOT a shell string)
            timeout:        Max execution time in seconds
            cwd:            Working directory (defaults to SCAN_OUTPUT_DIR)
            env_extra:      Extra env vars to merge into the process env
            stream:         Callable(level, line) for real-time log streaming
            mask_patterns:  List of regex patterns whose matches get masked in logs

        Returns:
            {
                "returncode": int,
                "stdout":     str (truncated if huge),
                "stderr":     str,
                "truncated":  bool,
                "timed_out":  bool,
            }
        """
        cmd = [self.tool_path] + [str(a) for a in args]

        work_dir = cwd or SCAN_OUTPUT_DIR
        os.makedirs(work_dir, exist_ok=True)

        env = os.environ.copy()
        env["PATH"] = f"{TOOLS_BIN_DIR}:{env.get('PATH', '')}"
        # Force HOME to /opt/tools so all tools (subfinder, katana, nuclei, etc.)
        # store their configs/cache under the shared volume instead of /app.
        # Must be a direct assignment (not setdefault) because os.environ.copy()
        # already carries the container's HOME=/app.
        env["HOME"] = "/opt/tools"
        if env_extra:
            env.update(env_extra)

        stdout_chunks: list[bytes] = []
        stderr_chunks: list[bytes] = []
        total_bytes = 0
        truncated = False
        timed_out = False

        def _drain_stream(pipe, chunks_list, level: str):
            nonlocal total_bytes, truncated
            for raw_line in iter(pipe.readline, b""):
                if total_bytes >= MAX_OUTPUT_BYTES:
                    truncated = True
                    continue
                chunks_list.append(raw_line)
                total_bytes += len(raw_line)
                if stream:
                    line = raw_line.decode("utf-8", errors="replace").rstrip()
                    line = self._mask(line, mask_patterns)
                    stream(level, line)

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=work_dir,
                env=env,
                # No shell=True — SECURITY CRITICAL
            )

            t_out = threading.Thread(target=_drain_stream, args=(proc.stdout, stdout_chunks, "info"), daemon=True)
            t_err = threading.Thread(target=_drain_stream, args=(proc.stderr, stderr_chunks, "warn"), daemon=True)
            t_out.start()
            t_err.start()

            try:
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                timed_out = True
            finally:
                t_out.join(timeout=5)
                t_err.join(timeout=5)

        except FileNotFoundError:
            raise ToolNotFoundError(f"Binary not found: {self.tool_path}")

        return {
            "returncode": proc.returncode,
            "stdout": b"".join(stdout_chunks).decode("utf-8", errors="replace"),
            "stderr": b"".join(stderr_chunks).decode("utf-8", errors="replace"),
            "truncated": truncated,
            "timed_out": timed_out,
        }

    @staticmethod
    def _mask(text: str, patterns: list[str] | None) -> str:
        if not patterns:
            return text
        for pattern in patterns:
            text = re.sub(pattern, "***MASKED***", text, flags=re.IGNORECASE)
        return text

    def output_file_path(self, job_id: str, ext: str = "json") -> Path:
        """Return a deterministic per-job output file path."""
        job_dir = Path(SCAN_OUTPUT_DIR) / job_id
        job_dir.mkdir(parents=True, exist_ok=True)
        return job_dir / f"{self.tool_name}_output.{ext}"

    def cleanup_output(self, job_id: str) -> None:
        """LOW-07: Delete per-job output directory after findings have been parsed.

        Called by BaseModule.execute() after _save_findings(). Prevents /tmp/pentools
        from filling up over thousands of scans and crashing subsequent runs.
        """
        import shutil
        job_dir = Path(SCAN_OUTPUT_DIR) / job_id
        if job_dir.exists():
            shutil.rmtree(job_dir, ignore_errors=True)
