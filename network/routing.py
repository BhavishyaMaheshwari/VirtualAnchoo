"""Enable or disable IPv4 forwarding only inside the lab router namespace."""
import argparse
import json
from .client import request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["enable", "disable", "status"])
    args = parser.parse_args()
    print(json.dumps(request("inspect") if args.mode == "status" else
                     request("routing", {"enabled": args.mode == "enable"}), indent=2))

if __name__ == "__main__":
    main()
