import json
import os
import ssl
from urllib.request import Request, urlopen


READ_ONLY_RESOURCES = frozenset({
    "nsconfig", "nsversion", "hanode", "lbvserver", "csvserver", "csaction",
    "cspolicy", "appfwprofile", "appfwpolicy", "appfwsignatures",
})


class NitroError(RuntimeError):
    pass


class NitroClient:
    """Small read-only NITRO client; credentials stay in process memory."""

    def __init__(self, endpoint: str | None = None, insecure_skip_verify: bool = False):
        self.endpoint = (endpoint or os.environ.get("NETSCALER_ENDPOINT", "https://192.168.11.101")).rstrip("/")
        self.insecure_skip_verify = insecure_skip_verify
        self._headers = {
            "X-NITRO-USER": os.environ.get("NS_LOGIN", ""),
            "X-NITRO-PASS": os.environ.get("NS_PASSWORD", ""),
            "Accept": "application/json",
        }
        if not self._headers["X-NITRO-USER"] or not self._headers["X-NITRO-PASS"]:
            raise NitroError("Set NS_LOGIN and NS_PASSWORD in the process environment")

    def get(self, resource: str) -> dict:
        if resource not in READ_ONLY_RESOURCES:
            raise ValueError(f"Resource is not in the read-only allow-list: {resource}")
        request = Request(f"{self.endpoint}/nitro/v1/config/{resource}", headers=self._headers, method="GET")
        context = ssl._create_unverified_context() if self.insecure_skip_verify else None
        try:
            with urlopen(request, timeout=15, context=context) as response:
                return json.load(response)
        except Exception as exc:
            raise NitroError(f"Read-only NITRO GET failed for {resource}: {exc}") from exc
