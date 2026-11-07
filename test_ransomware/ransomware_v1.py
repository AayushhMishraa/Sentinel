#!/usr/bin/env python3
"""ransomware_v1: a HARMLESS test tool that imitates simple ransomware.

It overwrites files with random bytes (like encryption would), about 20 files/sec.
It REFUSES to run anywhere except a marked sandbox (see _sandbox_guard.py).
Never point it at real data, and only run it inside your Linux test environment.

  --avoid-decoys   skip the bait files, so Rewind has to catch it by SPEED + ENTROPY
                   instead of by the decoy shortcut
  --rate N         files per second (default 20)
  --hold SECONDS   keep each file open this long after writing it (default 0.04). This
                   imitates the time real ransomware needs to encrypt, and is what lets
                   Rewind see which process is writing.
  --limit N        stop after N files
  --target PATH    folder to attack (must still be a marked sandbox)
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
    parser = argparse.ArgumentParser(description="Harmless ransomware simulator (v1).")
    parser.add_argument("--target", default=config.PROTECTED_DIR)
    parser.add_argument("--rate", type=float, default=20.0)
    parser.add_argument("--hold", type=float, default=0.04)
    parser.add_argument("--avoid-decoys", action="store_true")
    parser.add_argument("--limit", type=int, default=None)
    return parser.parse_args(argv)


def encrypt_file(path, hold):
    """Overwrite a file in place with random bytes of the same size."""
    with open(path, "r+b") as f:
        size = os.fstat(f.fileno()).st_size
        f.write(os.urandom(size))
        f.flush()
        if hold > 0:
            time.sleep(hold)       # the file stays open: "the encryption work takes time"


def run_sim_worker(argv=None):
    detach_stdin_and_ignore_signals()
    args = parse_args(argv)
    if args.rate <= 0:
        print("--rate must be above 0")
        return 2
    try:
        target = guard.validate_target(args.target)
    except guard.SandboxViolation as err:
        print("REFUSING TO RUN: %s" % err)
        return 2
    files = guard.safe_files(target, args.avoid_decoys)
    if args.limit is not None:
        files = files[:max(0, args.limit)]
    interval = 1.0 / args.rate
    hold = min(args.hold, interval * 0.8)
    print("ransomware_v1 (harmless test tool): attacking %d files in %s" % (len(files), target),
          flush=True)
    done = 0
    for path in files:
        started = time.time()
        try:
            encrypt_file(path, hold)
        except OSError as err:
            print("skipped %s: %s" % (os.path.basename(path), err), flush=True)
            continue
        done += 1
        rest = interval - (time.time() - started)
        if rest > 0:
            time.sleep(rest)
    print("finished: %d files overwritten" % done, flush=True)
    return 0


def run_supervised_cli():
    """Spawn worker in an independent session (start_new_session=True) so terminal suspension signals (SIGSTOP/SIGTSTP) never freeze the shell."""
    env = dict(os.environ, _RANSOMWARE_V1_WORKER="1")
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
                if ret < 0:
                    sig = -ret
                    if sig == signal.SIGKILL:
                        sys.stderr.write("Killed\n")
                    elif sig == signal.SIGTERM:
                        sys.stderr.write("Terminated\n")
                return 137 if ret == -signal.SIGKILL else (ret if ret >= 0 else 0)

            time.sleep(0.02)
    except (KeyboardInterrupt, SystemExit):
        try:
            proc.terminate()
        except OSError:
            pass
        return 0


def main(argv=None):
    if argv is not None or os.environ.get("_RANSOMWARE_V1_WORKER") == "1":
        return run_sim_worker(argv)
    return run_supervised_cli()


if __name__ == "__main__":
    sys.exit(main())
