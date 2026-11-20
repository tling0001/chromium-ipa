#!/usr/bin/env python3
"""Register requested iOS devices with App Store Connect and list all active iPhones."""
from __future__ import annotations

import json
import os
import re
import sys
import time
from urllib.parse import urlparse

import jwt
import requests

API = "https://api.appstoreconnect.apple.com/v1"
UDID_RE = re.compile(r"^[0-9A-Fa-f]{40}$")


def required_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"Missing required GitHub secret/environment variable: {name}")
    return value


def make_token(key_id: str, issuer_id: str, private_key: str) -> str:
    now = int(time.time())
    return jwt.encode(
        {"iss": issuer_id, "iat": now, "exp": now + 900, "aud": "appstoreconnect-v1"},
        private_key,
        algorithm="ES256",
        headers={"kid": key_id, "typ": "JWT"},
    )


class AppleAPI:
    def __init__(self, token: str):
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        })

    def request(self, method: str, url: str, **kwargs):
        if url.startswith("/"):
            url = API + url
        parsed = urlparse(url)
        if parsed.scheme != "https" or parsed.netloc != "api.appstoreconnect.apple.com":
            raise RuntimeError(f"Refusing unexpected Apple API URL: {url}")
        response = self.session.request(method, url, timeout=45, **kwargs)
        if not response.ok:
            try:
                detail = json.dumps(response.json().get("errors", response.json()), indent=2)
            except Exception:
                detail = response.text[:2000]
            raise RuntimeError(f"Apple API {method} {url} returned HTTP {response.status_code}:\n{detail}")
        if response.status_code == 204:
            return {}
        return response.json()

    def list_devices(self) -> list[dict]:
        url = API + "/devices?filter[platform]=IOS&limit=200&fields[devices]=name,platform,udid,status,addedDate"
        devices: list[dict] = []
        while url:
            payload = self.request("GET", url)
            devices.extend(payload.get("data", []))
            url = payload.get("links", {}).get("next")
        return devices

    def register_device(self, udid: str, name: str) -> dict:
        return self.request("POST", "/devices", json={"data": {
            "type": "devices",
            "attributes": {"name": name, "platform": "IOS", "udid": udid},
        }}).get("data", {})


def parse_udids(raw: str) -> list[str]:
    values = [x.strip().upper() for x in re.split(r"[,;\s]+", raw or "") if x.strip()]
    invalid = [x for x in values if not UDID_RE.fullmatch(x)]
    if invalid:
        raise RuntimeError("Invalid iOS UDID(s). Each UDID must be exactly 40 hexadecimal characters: " + ", ".join(invalid))
    return list(dict.fromkeys(values))


def main() -> int:
    key_id = required_env("APPLE_API_KEY_ID")
    issuer_id = required_env("APPLE_API_ISSUER_ID")
    private_key = required_env("APPLE_API_KEY_P8").replace("\\n", "\n")
    requested = parse_udids(os.environ.get("DEVICE_UDIDS", ""))
    name_prefix = os.environ.get("DEVICE_NAME_PREFIX", "Chromium sideload").strip() or "Chromium sideload"

    api = AppleAPI(make_token(key_id, issuer_id, private_key))
    devices = api.list_devices()
    by_udid = {d.get("attributes", {}).get("udid", "").upper(): d for d in devices}

    registered_now = []
    for udid in requested:
        existing = by_udid.get(udid)
        if existing:
            attrs = existing.get("attributes", {})
            status = attrs.get("status", "UNKNOWN")
            print(f"Already registered: {udid} ({attrs.get('name', 'unnamed')}, status={status})")
            if status != "ENABLED":
                raise RuntimeError(f"UDID {udid} is already registered but its status is {status}; enable it in the Apple Developer portal before provisioning.")
            continue

        short = udid[-8:]
        name = f"{name_prefix} {short}"
        created = api.register_device(udid, name)
        attrs = created.get("attributes", {})
        registered_now.append(udid)
        print(f"Registered: {udid} ({attrs.get('name', name)}, status={attrs.get('status', 'processing')})")

    # Refresh after registration so the report reflects Apple's current state.
    devices = api.list_devices()
    active = []
    not_ready = []
    for device in devices:
        attrs = device.get("attributes", {})
        if attrs.get("status") == "ENABLED":
            active.append({
                "udid": attrs.get("udid"),
                "name": attrs.get("name"),
                "addedDate": attrs.get("addedDate"),
            })
        elif attrs.get("status") in ("PROCESSING", "DISABLED"):
            not_ready.append({
                "udid": attrs.get("udid"),
                "name": attrs.get("name"),
                "status": attrs.get("status"),
            })

    active.sort(key=lambda x: (x.get("name") or "", x.get("udid") or ""))
    print("")
    print(f"Apple team currently has {len(devices)} registered iOS device(s); {len(active)} are ENABLED and eligible for profiles.")
    print(f"New registrations in this run: {len(registered_now)}.")
    if not_ready:
        print(f"{len(not_ready)} device(s) are not currently eligible (PROCESSING or DISABLED).")
        for item in not_ready:
            print(f"  {item['udid']} — {item['status']}")

    report = {
        "registered_this_run": registered_now,
        "active_devices": active,
        "not_ready_devices": not_ready,
        "total_registered_ios_devices": len(devices),
    }
    with open(os.environ.get("GITHUB_WORKSPACE", ".") + "/apple-device-report.json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    if not active:
        raise RuntimeError("The Apple team has no ENABLED iOS devices. Add a UDID in the workflow input and retry after Apple processes it.")
    print(f"Eligible device UDIDs: {len(active)} (full list written to apple-device-report.json)")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"::error::{exc}", file=sys.stderr)
        raise
