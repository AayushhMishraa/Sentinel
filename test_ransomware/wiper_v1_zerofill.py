#!/usr/bin/env python3
"""wiper_v1_zerofill: a HARMLESS test tool that imitates a WIPER: files are overwritten with zeros.

Zeros have entropy 0 (the opposite of encryption), so the ENTROPY signal never fires; only the
SPEED signal and the sustained-suspicion rule can catch it. It also checks that a restore never
brings zeros back as "known good".
It REFUSES to run anywhere except a marked sandbox (see _sandbox_guard.py).

  --rate N         files per second (default 12)       --limit N       stop after N files
  --hold SECONDS   keep each file open this long       --target PATH   folder to attack
                   after writing it (default 0.04)     --avoid-decoys  skip the !DECOY_ files
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
    p = argparse.ArgumentParser(description="Harmless zero-fill wiper simulator.")
    p.add_argument("--target", default=config.PROTECTED_DIR)
    p.add_argument("--rate", type=float, default=12.0)
    p.add_argument("--hold", type=float, default=0.04)
    p.add_argument("--avoid-decoys", action="store_true")
    p.add_argument("--limit", type=int, default=None)
    return p.parse_args(argv)


def zero_fill(path, hold):
    """Overwrite a file in place with zero bytes (same size); keep it open for `hold` seconds."""
    with open(path, "r+b") as f:
        size = os.fstat(f.fileno()).st_size
        f.write(bytes(size))
        f.flush()
        if hold > 0:
            time.sleep(hold)


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
    print("wiper_v1_zerofill (harmless test tool): wiping %d files in %s" % (len(files), target),
          flush=True)
    done = 0
    for path in files:
        started = time.time()
        try:
            zero_fill(path, hold)
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
    env = dict(os.environ, _WIPER_V1_WORKER="1")
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
    if argv is not None or os.environ.get("_WIPER_V1_WORKER") == "1":
        return run_sim_worker(argv)
    return run_supervised_cli()


if __name__ == "__main__":
    sys.exit(main())
