# icmpx/__main__.py
import argparse
import os
import shutil
import subprocess
import sys

from .demo import run
from ._exceptions import RawSocketPermissionError


def grant_capability(executable: str) -> int:
    if not shutil.which("setcap"):
        print("setcap not found. Install (e.g.: sudo apt install libcap2-bin).")
        return 1
    cmd = ["sudo", "setcap", "cap_net_raw+ep", executable]
    print(f"Executing: {' '.join(cmd)}")
    return subprocess.call(cmd)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="icmpx")
    parser.add_argument(
        "--bootstrap-cap",
        action="store_true",
        help="Configure CAP_NET_RAW in the uvx interpreter.",
    )
    args, remaining = parser.parse_known_args(argv)

    if args.bootstrap_cap:
        exe = os.path.realpath(sys.executable)
        print(f"Applying CAP_NET_RAW to {exe}")
        return grant_capability(exe)

    try:
        if remaining:
            print("Ignoring extra CLI arguments:", " ".join(remaining))
        run()
        return 0
    except RawSocketPermissionError:
        exe = os.path.realpath(sys.executable)
        print("\nError: the interpreter does not have CAP_NET_RAW.")
        print("Execute once:")
        print("  uvx icmpx --bootstrap-cap")
        print("and provide the sudo password when prompted.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
