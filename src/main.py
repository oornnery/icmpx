"""
Ja no ambiente virtual (venv)
Use `sudo setcap cap_net_raw+ep $(realpath $(which python))`
"""

from _icmp import Icmp, console

if __name__ == "__main__":
    target = "8.8.8.8"
    with Icmp() as icmp:
        ex1 = icmp.ping(target)
        console.print(ex1)
        ex2 = icmp.multiping(target)
        console.print(ex2)
        ex3 = icmp.traceroute(target, resolve_dns=True)
        console.print(ex3)
        ex4 = icmp.mtr(target, resolve_dns=True)
        console.print(ex4)
