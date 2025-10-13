from icmpx import Client
from rich import print


def main():
    with Client() as client:
        echo = client.ping("8.8.8.8", count=3)
        for echo in echo:
            print(str(echo))


if __name__ == "__main__":
    main()
