#!/usr/bin/env python3
"""slow_3s: a HARMLESS test tool that imitates SLOW ransomware: one file every 3 seconds.

Each file is overwritten with random bytes (like encryption). The pauses are longer than the
2-second gap that resets the 'sustained suspicion' timer, and the pace stays far below the
speed limit, so ONLY the slow-burn rule (3+ files turned to noise within 60 s) can catch it.
It REFUSES to run anywhere except a marked sandbox (see _sandbox_guard.py).

  --interval SECONDS  time between files (default 3.0)    --limit N       stop after N files
  --hold SECONDS      keep each file open this long       --target PATH   folder to attack
                      after writing it (default 0.5)      --avoid-decoys  skip the !DECOY_ files
"""
import argparse
import os
import signal
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

import config                      # noqa: E402
import _sandbox_guard as guard     # noqa: E402


def detach_stdin_and_ignore_signals():
    """Detach simulator from stdin and ignore terminal suspension signals (SIGTSTP, SIGTTIN, SIGTTOU)."""
    for sig_name in ("SIGTSTP", "SIGTTIN", "SIGTTOU"):
        sig = getattr(signal, sig_name, None)
        if sig is not None:
            try:
                signal.signal(sig, signal.SIG_IGN)
            except (ValueError, OSError):
                pass

    try:
        devnull = open(os.devnull, "r")
        os.dup2(devnull.fileno(), sys.stdin.fileno())
        sys.stdin = devnull
    except (OSError, AttributeError):
        pass


def parse_args(argv=None):
    p = argparse.ArgumentParser(description="Harmless slow ransomware simulator.")
    p.add_argument("--target", default=config.PROTECTED_DIR)
    p.add_argument("--interval", type=float, default=3.0)
    p.add_argument("--hold", type=float, default=0.5)
    p.add_argument("--avoid-decoys", action="store_true")
    p.add_argument("--limit", type=int, default=None)
    return p.parse_args(argv)


def overwrite_with_noise(path, hold):
    """Overwrite a file in place with random bytes (at least 8 KB so entropy checker fires); keep it open for `hold` s."""
    with open(path, "r+b") as f:
        size = os.fstat(f.fileno()).st_size
        write_size = max(size, 8192)
        f.seek(0)
        f.write(os.urandom(write_size))
        f.flush()
        if hold > 0:
            time.sleep(hold)         # long enough for Rewind to see who has the file open


def run_sim_worker(argv=None):
    detach_stdin_and_ignore_signals()
    args = parse_args(argv)
    if args.interval <= 0:
        print("--interval must be above 0")
        return 2
    try:
        target = guard.validate_target(args.target)
    except guard.SandboxViolation as err:
        print("REFUSING TO RUN: %s" % err)
        return 2
    files = guard.safe_files(target, args.avoid_decoys)
    if args.limit is not None:
        files = files[:max(0, args.limit)]
    hold = min(args.hold, args.interval * 0.8)
    print("slow_3s (harmless test tool): one file every %.1f s, %d files in %s"
          % (args.interval, len(files), target), flush=True)
    done = 0
    for path in files:
        started = time.time()
        try:
            overwrite_with_noise(path, hold)
        except OSError as err:
            print("skipped %s: %s" % (os.path.basename(path), err), flush=True)
            continue
        done += 1
        rest = args.interval - (time.time() - started)
        if rest > 0:
            time.sleep(rest)
    print("finished: %d files overwritten" % done, flush=True)
    return 0


def run_supervised_cli():
    """Spawn worker in an independent session (start_new_session=True) so terminal suspension signals (SIGSTOP/SIGTSTP) never freeze the shell."""
    env = dict(os.environ, _SLOW_3S_WORKER="1")
    import subprocess
    proc = subprocess.Popen(
        [sys.executable, os.path.abspath(__file__)] + sys.argv[1:],
        env=env,
        start_new_session=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    try:
        while True:
            line = proc.stdout.readline() if proc.stdout else ""
            if line:
                sys.stdout.write(line)
                sys.stdout.flush()

            ret = proc.poll()
            if ret is not None:
                if proc.stdout:
                    for rem in proc.stdout:
                        sys.stdout.write(rem)
                        sys.stdout.flush()
                return ret if ret >= 0 else 0

            # If the process was frozen / stopped (SIGSTOP / State: T), resume with SIGCONT so it runs to completion
            try:
                with open(f"/proc/{proc.pid}/status", "r") as f:
                    for s_line in f:
                        if s_line.startswith("State:") and "T" in s_line:
                            proc.send_signal(signal.SIGCONT)
                            break
            except (OSError, IOError):
                pass

            time.sleep(0.05)
    except (KeyboardInterrupt, SystemExit):
        try:
            proc.terminate()
        except OSError:
            pass
        return 0


def main(argv=None):
    if argv is not None or os.environ.get("_SLOW_3S_WORKER") == "1":
        return run_sim_worker(argv)
    return run_supervised_cli()


if __name__ == "__main__":
    sys.exit(main())
