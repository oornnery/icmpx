"""Runtime helpers for the icmpx package."""

from __future__ import annotations

from . import Icmp, console, mtr, multiping, traceroute


def run(target: str = "8.8.8.8") -> None:
   """Execute the demo workflow against the given target."""
   with Icmp() as icmp:
      ex1 = icmp.ping(target)
      console.print(ex1)

      ex2 = multiping(icmp, target)
      console.print(ex2)

      ex3 = traceroute(icmp, target, resolve_dns=True)
      console.print(ex3)

      ex4 = mtr(icmp, target, resolve_dns=True)
      console.print(ex4)


if __name__ == "__main__":
   run()
