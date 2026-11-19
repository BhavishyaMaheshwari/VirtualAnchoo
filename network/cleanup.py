"""Stop the owned lab through its agent; never use global `mn -c` cleanup."""
import json
from .client import request, LabUnavailable


def main():
    try:
        result = request("shutdown")
    except LabUnavailable:
        result = {"stopping": False, "message": "No reachable agent. No host interfaces or unrelated OVS bridges were modified. Inspect any orphaned ns-* resources manually."}
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()
