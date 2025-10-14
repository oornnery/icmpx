# icmpx/__main__.py
import argparse
import os
import shlex
import shutil
import subprocess
import sys

from rich.console import Console
from rich.panel import Panel

from ._exceptions import RawSocketPermissionError
from .demo import run


console = Console()


def grant_capability(executable: str) -> int:
    if not shutil.which("setcap"):
        console.print(
            Panel(
                "`setcap` not found. Install it (e.g.: sudo apt install libcap2-bin) and try again.",
                title="Missing Dependency",
                border_style="red",
            )
        )
        return 1
    cmd = ["sudo", "setcap", "cap_net_raw+ep", executable]
    console.print(f"[bold cyan]Executing:[/] {shlex.join(cmd)}")
    return subprocess.call(cmd)


def has_capability(executable: str) -> bool | None:
    if os.name != "posix":
        return True
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return True
    getcap = shutil.which("getcap")
    if not getcap:
        return None
    try:
        result = subprocess.run(
            [getcap, executable],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return None
    output = (result.stdout or "").strip()
    if not output:
        return False
    return "cap_net_raw" in output and ("=ep" in output or "+ep" in output)


def print_permission_hint(executable: str) -> None:
    quoted = shlex.quote(executable)
    console.print(
        Panel(
            "\n".join(
                [
                    "The interpreter does not have [bold]CAP_NET_RAW[/].",
                    "Execute once:",
                    "  [bold]uvx icmpx --bootstrap-cap[/]",
                    "or apply it manually:",
                    f"  [bold]sudo setcap cap_net_raw+ep {quoted}[/]",
                    "If this keeps failing, ensure libcap is installed and retry.",
                ]
            ),
            title="Permission Required",
            border_style="red",
        )
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="icmpx")
    parser.add_argument(
        "--bootstrap-cap",
        action="store_true",
        help="Configure CAP_NET_RAW in the uvx interpreter.",
    )
    args, remaining = parser.parse_known_args(argv)
    exe = os.path.realpath(sys.executable)

    if args.bootstrap_cap:
        console.print(Panel.fit(f"Applying CAP_NET_RAW to [bold]{exe}[/]", title="Bootstrap", border_style="cyan"))
        result = grant_capability(exe)
        if result != 0:
            return result

        status = has_capability(exe)
        if status is False:
            console.print(
                Panel(
                    "Capability command completed, but verification still failed.",
                    title="Verification Failed",
                    border_style="red",
                )
            )
            print_permission_hint(exe)
            return 1
        if status is None:
            console.print(
                Panel(
                    "Could not verify CAP_NET_RAW automatically (missing getcap?).",
                    title="Warning",
                    border_style="yellow",
                )
            )
        else:
            console.print(
                Panel(
                    "Capability confirmed. Launching icmpx demo...",
                    title="Ready",
                    border_style="green",
                )
            )

        if remaining:
            console.print(
                Panel.fit(
                    f"Ignoring extra CLI arguments: {' '.join(remaining)}",
                    title="Info",
                    border_style="blue",
                )
            )

        try:
            run()
            return 0
        except RawSocketPermissionError:
            console.print(
                Panel(
                    "Raw socket still unavailable even after applying capability.",
                    title="Error",
                    border_style="red",
                )
            )
            print_permission_hint(exe)
            return 1

    status = has_capability(exe)
    if status is False:
        print_permission_hint(exe)
        return 1
    if status is None:
        console.print(
            Panel(
                "Could not verify CAP_NET_RAW automatically (missing getcap?). Attempting to launch anyway.",
                title="Warning",
                border_style="yellow",
            )
        )

    try:
        if remaining:
            console.print(
                Panel.fit(
                    f"Ignoring extra CLI arguments: {' '.join(remaining)}",
                    title="Info",
                    border_style="blue",
                )
            )
        run()
        return 0
    except RawSocketPermissionError:
        print_permission_hint(exe)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
