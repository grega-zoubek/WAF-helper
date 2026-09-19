import json

from app.netscaler.discovery import snapshot
from app.netscaler.nitro import NitroClient


def main() -> None:
    print(json.dumps(snapshot(NitroClient(insecure_skip_verify=True)), indent=2))


if __name__ == "__main__":
    main()
