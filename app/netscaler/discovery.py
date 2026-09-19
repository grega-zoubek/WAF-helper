from app.netscaler.nitro import NitroClient


def _items(payload: dict, resource: str) -> list[dict]:
    value = payload.get(resource, [])
    return value if isinstance(value, list) else [value]


def snapshot(client: NitroClient) -> dict:
    """Collect a sanitized, structured ADC snapshot for assessment input."""
    names = ("nsconfig", "nsversion", "hanode", "lbvserver", "csvserver", "csaction", "cspolicy", "appfwprofile", "appfwpolicy", "appfwsignatures")
    data = {name: client.get(name) for name in names}
    nsconfig = _items(data["nsconfig"], "nsconfig")
    signatures = data["appfwsignatures"]
    return {
        "adc": {
            "ipaddress": nsconfig[0].get("ipaddress") if nsconfig else None,
            "systemtype": nsconfig[0].get("systemtype") if nsconfig else None,
            "release": _items(data["nsversion"], "nsversion"),
            "ha": _items(data["hanode"], "hanode"),
        },
        "counts": {name: len(_items(data[name], name)) for name in names},
        "lbvservers": [{k: item.get(k) for k in ("name", "ipv46", "port", "servicetype", "curstate", "effectivestate")} for item in _items(data["lbvserver"], "lbvserver")],
        "csvservers": [{k: item.get(k) for k in ("name", "ipv46", "port", "servicetype", "curstate", "vserver")} for item in _items(data["csvserver"], "csvserver")],
        "csactions": [{k: item.get(k) for k in ("name", "targetlbvserver", "referencecount")} for item in _items(data["csaction"], "csaction")],
        "cspolicies": [{k: item.get(k) for k in ("policyname", "rule", "action", "priority", "activepolicy")} for item in _items(data["cspolicy"], "cspolicy")],
        "appfwprofiles": [{k: item.get(k) for k in ("name", "state", "learning", "signatures", "sqlinjectionaction", "crosssitescriptingaction", "jsonsqlinjectionaction")} for item in _items(data["appfwprofile"], "appfwprofile")],
        "signature_feed": {k: signatures.get(k) for k in ("src", "encryptedversion")},
    }
