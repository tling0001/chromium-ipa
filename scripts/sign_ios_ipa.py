#!/usr/bin/env python3
"""Re-sign an unsigned Chromium iOS app using matching provisioning profiles."""
import fnmatch, plistlib, subprocess, sys, tempfile
from pathlib import Path
REQUIRED = "com.apple.developer.kernel.extended-virtual-addressing"
def run(*args, capture=False):
    p = subprocess.run(args, check=True, text=True, stdout=subprocess.PIPE if capture else None, stderr=subprocess.PIPE if capture else None)
    return p.stdout if capture else ""
def profile_data(path):
    return plistlib.loads(run("security", "cms", "-D", "-i", str(path), capture=True).encode())
def bid(bundle):
    value = plistlib.loads((bundle / "Info.plist").read_bytes()).get("CFBundleIdentifier")
    if not value: raise RuntimeError(f"Missing CFBundleIdentifier in {bundle}")
    return value
def main():
    if len(sys.argv) != 4: raise SystemExit("usage: sign_ios_ipa.py APP_BUNDLE PROFILES_DIR SIGNING_IDENTITY")
    root, profiles_dir, identity = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
    if not root.is_dir() or root.suffix != ".app": raise RuntimeError(f"Not an .app bundle: {root}")
    profiles = []
    for path in profiles_dir.rglob("*.mobileprovision"):
        ent = profile_data(path).get("Entitlements", {})
        app_id = ent.get("application-identifier", "")
        if app_id: profiles.append((path, ent, app_id))
    if not profiles: raise RuntimeError("No usable .mobileprovision files found in profiles ZIP.")
    bundles = [p for p in root.rglob("*") if p.is_dir() and p.suffix in (".appex", ".app")] + [root]
    bundles = sorted(set(bundles), key=lambda p: len(p.parts), reverse=True)
    selected = {}
    for bundle in bundles:
        app_bundle_id = bid(bundle)
        matches = [x for x in profiles if "." in x[2] and fnmatch.fnmatchcase(app_bundle_id, x[2].split(".", 1)[1])]
        if not matches: raise RuntimeError(f"No profile matches {app_bundle_id}; include profiles for every .app/.appex.")
        selected[bundle] = max(matches, key=lambda x: len(x[2].replace("*", "")))
    if selected[root][1].get(REQUIRED) is not True:
        raise RuntimeError(f"Main app profile does not authorize {REQUIRED}=true. Adding it to the IPA cannot override Apple's profile restrictions.")
    code = []
    for p in root.rglob("*"):
        if (p.is_dir() and p.suffix == ".framework") or (p.is_file() and p.suffix == ".dylib"): code.append(p)
    for p in sorted(code, key=lambda x: len(x.parts), reverse=True):
        run("codesign", "--force", "--sign", identity, "--timestamp=none", str(p))
    for bundle in bundles:
        profile_path, ent, _ = selected[bundle]
        (bundle / "embedded.mobileprovision").write_bytes(profile_path.read_bytes())
        with tempfile.NamedTemporaryFile(suffix=".plist", delete=False) as tmp:
            ep = Path(tmp.name); ep.write_bytes(plistlib.dumps(ent, fmt=plistlib.FMT_XML, sort_keys=True))
        try: run("codesign", "--force", "--sign", identity, "--timestamp=none", "--entitlements", str(ep), str(bundle))
        finally: ep.unlink(missing_ok=True)
    run("codesign", "--verify", "--deep", "--strict", "--verbose=2", str(root))
    print(f"Signed and verified {root.name}; profile authorizes {REQUIRED}=true")
if __name__ == "__main__":
    try: main()
    except subprocess.CalledProcessError as e:
        print(f"Signing command failed: {e}", file=sys.stderr); raise
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr); raise
