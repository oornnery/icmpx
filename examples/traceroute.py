from icmpx import Client
from rich import print

def main():
    with Client() as client:
        tr = client.traceroute("8.8.8.8", resolve_dns=True)
        print(str(tr))


if __name__ == "__main__":
    main()