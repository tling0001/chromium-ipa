#!/usr/bin/env python3
"""Automate Apple Ad Hoc provisioning and sign an iOS IPA using a Team API key."""
from __future__ import annotations
import base64, hashlib, json, os, re, secrets, subprocess, sys, time
from pathlib import Path
from urllib.parse import quote, urlparse
import jwt, plistlib, requests
from nacl.public import PublicKey, SealedBox

API = "https://api.appstoreconnect.apple.com/v1"
P12_SECRET = "APPLE_AUTO_SIGNING_P12_BASE64"
PASS_SECRET = "APPLE_AUTO_SIGNING_P12_PASSWORD"
DEV_P12_SECRET = "APPLE_AUTO_SIGNING_DEV_P12_BASE64"
DEV_PASS_SECRET = "APPLE_AUTO_SIGNING_DEV_P12_PASSWORD"
EVA = "com.apple.developer.kernel.extended-virtual-addressing"

def env(k, default=""): return os.environ.get(k, default).strip()
def run(*args, capture=False):
    p = subprocess.run(args, check=True, text=True, stdout=subprocess.PIPE if capture else None, stderr=subprocess.PIPE if capture else None)
    return p.stdout if capture else ""

def token():
    kid, issuer, key = env("APPLE_API_KEY_ID"), env("APPLE_API_ISSUER_ID"), env("APPLE_API_KEY_P8").replace("\\n", "\n")
    if not all((kid, issuer, key)): raise RuntimeError("Missing APPLE_API_KEY_P8, APPLE_API_KEY_ID, or APPLE_API_ISSUER_ID.")
    now = int(time.time())
    return jwt.encode({"iss":issuer,"iat":now,"exp":now+900,"aud":"appstoreconnect-v1"}, key, algorithm="ES256", headers={"kid":kid,"typ":"JWT"})

class Apple:
    def __init__(self):
        self.s=requests.Session()
        self.s.headers.update({"Authorization":"Bearer "+token(),"Accept":"application/json","Content-Type":"application/json"})
    def req(self, method, path, **kw):
        url=path if path.startswith("https://") else API+path
        u=urlparse(url)
        if u.scheme!="https" or u.netloc!="api.appstoreconnect.apple.com": raise RuntimeError("Unexpected Apple API URL: "+url)
        r=self.s.request(method,url,timeout=60,**kw)
        if not r.ok:
            try: detail=json.dumps(r.json().get("errors",r.json()),indent=2)
            except Exception: detail=r.text[:2500]
            raise RuntimeError(f"Apple API {method} returned HTTP {r.status_code}: {detail}")
        return {} if r.status_code==204 else r.json()
    def pages(self,path):
        out=[]; url=API+path
        while url:
            x=self.req("GET",url); out+=x.get("data",[]); url=x.get("links",{}).get("next")
        return out
    def devices(self): return self.pages("/devices?filter[platform]=IOS&limit=200&fields[devices]=name,platform,udid,status")
    def appid(self,bid):
        for x in self.pages("/bundleIds?filter[identifier]="+quote(bid,safe="")+"&filter[platform]=IOS&limit=200"):
            if x.get("attributes",{}).get("identifier")==bid: return x["id"]
        # App ID display names are stricter than bundle identifiers: Apple
        # accepts only ASCII letters, digits, and spaces (no dots/underscores).
        display_name=re.sub(r"[^A-Za-z0-9 ]+", " ", "Chromium "+bid)
        display_name=" ".join(display_name.split())[:100] or "Chromium iOS"
        x=self.req("POST","/bundleIds",json={"data":{"type":"bundleIds","attributes":{"identifier":bid,"name":display_name,"platform":"IOS"}}})
        print("Created App ID:",bid); return x["data"]["id"]
    def ensure_capability(self,bundle_id_id,capability):
        # Apple does not allow the generic collection `limit` parameter on this relationship endpoint.
        current=self.pages(f"/bundleIds/{bundle_id_id}/bundleIdCapabilities")
        if any(x.get("attributes",{}).get("capabilityType")==capability for x in current):
            print(f"Capability already enabled: {capability}")
            return
        self.req("POST","/bundleIdCapabilities",json={"data":{"type":"bundleIdCapabilities","attributes":{"capabilityType":capability},"relationships":{"bundleId":{"data":{"type":"bundleIds","id":bundle_id_id}}}}})
        print(f"Enabled capability: {capability}")
    def certs(self,certificate_type):
        # Do not request/require the undocumented "activated" field: the
        # Certificates API may omit it even for a valid current certificate.
        return self.pages(f"/certificates?filter[certificateType]={certificate_type}&limit=200&fields[certificates]=certificateType,serialNumber,expirationDate")
    def create_cert(self,work,certificate_type):
        key=work/"signing.key"; csr=work/"signing.csr"
        run("openssl","genrsa","-out",str(key),"2048")
        label="Development" if certificate_type=="IOS_DEVELOPMENT" else "Ad Hoc Distribution"
        run("openssl","req","-new","-key",str(key),"-out",str(csr),"-subj",f"/CN=Chromium iOS {label}")
        x=self.req("POST","/certificates",json={"data":{"type":"certificates","attributes":{"certificateType":certificate_type,"csrContent":csr.read_text()}}})["data"]
        der=work/"dist.cer"; der.write_bytes(base64.b64decode(x["attributes"]["certificateContent"]))
        cert=work/"dist.pem"; run("openssl","x509","-inform","DER","-in",str(der),"-out",str(cert))
        password=secrets.token_urlsafe(30); p12=work/"signing.p12"
        run("openssl","pkcs12","-export","-inkey",str(key),"-in",str(cert),"-out",str(p12),"-passout","pass:"+password,"-name",f"Chromium iOS {label}")
        print(f"Created {certificate_type} certificate:",x["attributes"].get("serialNumber",""))
        return p12,password
    def profile(self,name,bid_id,cert_id,device_ids,path,profile_type):
        # Replace only an existing profile with this exact generated name,
        # App ID, and profile type.
        for existing in self.pages(f"/profiles?filter[profileType]={profile_type}&limit=200"):
            if existing.get("attributes",{}).get("name") != name[:100]:
                continue
            pid=existing["id"]
            detail=self.req("GET",f"/profiles/{pid}?include=bundleId")
            rel=detail.get("data",{}).get("relationships",{}).get("bundleId",{}).get("data",{})
            if rel.get("id") != bid_id:
                continue
            print(f"Deleting duplicate {profile_type} profile {pid} for {name}; it will be regenerated.")
            self.req("DELETE",f"/profiles/{pid}")
        body={"data":{"type":"profiles","attributes":{"name":name[:100],"profileType":profile_type},"relationships":{
            "bundleId":{"data":{"type":"bundleIds","id":bid_id}},
            "certificates":{"data":[{"type":"certificates","id":cert_id}]},
            "devices":{"data":[{"type":"devices","id":d} for d in device_ids]}}}}
        x=self.req("POST","/profiles",json=body)["data"]
        path.write_bytes(base64.b64decode(x["attributes"]["profileContent"]))
        return x

def gh_secret(name,value):
    token=env("GH_SECRETS_TOKEN"); repo=env("GITHUB_REPOSITORY")
    if not token or not repo: raise RuntimeError("GH_SECRETS_TOKEN/repository missing; create a fine-grained token with repository Secrets: write permission to persist the signing identity.")
    s=requests.Session(); s.headers.update({"Authorization":"Bearer "+token,"Accept":"application/vnd.github+json","X-GitHub-Api-Version":"2022-11-28"})
    base=f"https://api.github.com/repos/{repo}/actions/secrets"
    r=s.get(base+"/public-key",timeout=30)
    if not r.ok: raise RuntimeError(f"Cannot get GitHub Actions secret public key: {r.status_code} {r.text[:800]}")
    k=r.json(); enc=base64.b64encode(SealedBox(PublicKey(base64.b64decode(k["key"]))).encrypt(value.encode())).decode()
    r=s.put(base+"/"+name,json={"encrypted_value":enc,"key_id":k["key_id"]},timeout=30)
    if not r.ok: raise RuntimeError(f"Cannot persist {name}: {r.status_code} {r.text[:1000]}")
    print("Saved encrypted repository secret:",name)

def cert_serial(p12,password,work):
    pem=work/"stored-cert.pem"
    run("openssl","pkcs12","-in",str(p12),"-clcerts","-nokeys","-passin","pass:"+password,"-out",str(pem))
    return run("openssl","x509","-in",str(pem),"-noout","-serial",capture=True).strip().split("=",1)[-1].lstrip("0").upper() or "0"

def signing_cert(apple,work,certificate_type):
    is_development=certificate_type=="IOS_DEVELOPMENT"
    p12_secret=DEV_P12_SECRET if is_development else P12_SECRET
    pass_secret=DEV_PASS_SECRET if is_development else PASS_SECRET
    b64,pw=env(p12_secret),env(pass_secret)
    if bool(b64)!=bool(pw): raise RuntimeError(f"Both {p12_secret} and {pass_secret} secrets must exist together.")
    if b64:
        p12=work/"saved.p12"; p12.write_bytes(base64.b64decode(b64))
        run("openssl","pkcs12","-in",str(p12),"-passin","pass:"+pw,"-noout")
        serial=cert_serial(p12,pw,work)
        for c in apple.certs(certificate_type):
            a=c.get("attributes",{}); s=(a.get("serialNumber") or "").replace(":","").lstrip("0").upper() or "0"
            # Missing "activated" is not evidence of revocation. Only reject
            # an explicit false value; Apple exposes expiration separately.
            if s==serial and a.get("activated") is not False:
                print(f"Reusing saved Apple {certificate_type} certificate:", c["id"])
                return p12,pw,c["id"]
        print("Saved certificate was not found in Apple's current certificate list; checking before requesting another.")
    p12,pw=apple.create_cert(work,certificate_type); serial=cert_serial(p12,pw,work); found=None
    for c in apple.certs(certificate_type):
        a=c.get("attributes",{}); s=(a.get("serialNumber") or "").replace(":","").lstrip("0").upper() or "0"
        if s==serial: found=c; break
    if not found:
        raise RuntimeError("New Apple certificate was created but is not yet visible in the API. Retry signing; the saved P12 will be reused once Apple lists it.")
    gh_secret(p12_secret,base64.b64encode(p12.read_bytes()).decode())
    gh_secret(pass_secret,pw)
    return p12,pw,found["id"]

def bid(bundle):
    x=plistlib.loads((bundle/"Info.plist").read_bytes()).get("CFBundleIdentifier")
    if not x: raise RuntimeError("Missing CFBundleIdentifier: "+str(bundle))
    return x

def is_macho(path):
    """Identify Mach-O code by its file type, not by its filename extension."""
    if path.is_symlink() or not path.is_file():
        return False
    description=run("file","-b",str(path),capture=True)
    return "Mach-O" in description

def profile_plist(path,work):
    raw=run("security","cms","-D","-i",str(path),capture=True)
    return plistlib.loads(raw.encode())

def sign_bundle(bundle,profile,identity,work,enabled_udids,team_id,expected_get_task_allow):
    data=profile_plist(profile,work); allowed=data.get("Entitlements",{})
    identifier=bid(bundle); appid=allowed.get("application-identifier","")
    prefix=appid.split(".",1)[0]
    expected_appid=prefix+"."+identifier
    if not prefix or appid != expected_appid:
        raise RuntimeError(f"Provisioning profile application-identifier mismatch for {identifier}: expected {expected_appid!r}, got {appid!r}.")
    prefixes=data.get("ApplicationIdentifierPrefix",[])
    teams=data.get("TeamIdentifier",[])
    if prefix not in prefixes or team_id not in teams or allowed.get("com.apple.developer.team-identifier") != team_id:
        raise RuntimeError(f"Provisioning profile team/prefix mismatch for {identifier}: prefix={prefix!r}, prefixes={prefixes!r}, team={teams!r}, entitlement_team={allowed.get('com.apple.developer.team-identifier')!r}, signing_team={team_id!r}.")
    expiry=data.get("ExpirationDate")
    if not expiry or expiry.timestamp() <= time.time():
        raise RuntimeError(f"Provisioning profile for {identifier} is missing an expiration date or has expired.")
    provisioned=data.get("ProvisionedDevices")
    if data.get("ProvisionsAllDevices") is True or not isinstance(provisioned,list) or not provisioned:
        raise RuntimeError(f"Provisioning profile for {identifier} is not a device-scoped Ad Hoc profile.")
    missing=sorted(set(enabled_udids)-set(provisioned))
    if missing:
        raise RuntimeError(f"Provisioning profile for {identifier} omits {len(missing)} enabled registered device(s): {', '.join(missing)}")
    if allowed.get("get-task-allow") is not expected_get_task_allow:
        expected="enable" if expected_get_task_allow else "disable"
        raise RuntimeError(f"Provisioning profile for {identifier} does not explicitly {expected} get-task-allow for this signing mode.")
    certs=data.get("DeveloperCertificates",[])
    identity_sha1=identity.replace(" ","").upper()
    profile_cert_hashes={hashlib.sha1(cert).hexdigest().upper() for cert in certs}
    if identity_sha1 not in profile_cert_hashes:
        raise RuntimeError(f"Provisioning profile for {identifier} does not contain the distribution certificate used to sign it (SHA-1 {identity_sha1}).")
    ent=dict(allowed); ent["application-identifier"]=prefix+"."+identifier
    if "com.apple.developer.team-identifier" in ent: ent["com.apple.developer.team-identifier"]=team_id
    if "keychain-access-groups" in ent:
        ent["keychain-access-groups"]=[x.replace("$(AppIdentifierPrefix)",prefix+".") for x in ent["keychain-access-groups"]]
    if allowed.get(EVA) is not True:
        print(f"::warning::Profile for {identifier} does not authorize {EVA}; signature will be valid only for allowed entitlements and the known startup crash may remain.")
    groups=allowed.get("com.apple.security.application-groups",[])
    expected={"group.com.tling0001.chrome","group.com.tling0001.common"}
    if not expected.issubset(set(groups)):
        missing=", ".join(sorted(expected-set(groups)))
        print(f"::warning::Profile for {identifier} is missing Chromium App Groups: {missing}. APP_GROUPS is enabled, but the group containers must be registered and assigned to this App ID in the Apple Developer portal.")
    (bundle/"embedded.mobileprovision").write_bytes(profile.read_bytes())
    ep=work/(re.sub(r"[^A-Za-z0-9_.-]","_",identifier)+".plist")
    ep.write_bytes(plistlib.dumps(ent,fmt=plistlib.FMT_XML,sort_keys=True))
    run("codesign","--force","--sign",identity,"--timestamp=none","--entitlements",str(ep),str(bundle))
    run("codesign","--verify","--strict","--verbose=2",str(bundle))
    details=subprocess.run(["codesign","-dv","--verbose=4",str(bundle)],text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True)
    signature=details.stdout+details.stderr
    signed_id=re.search(r"^Identifier=(.+)$",signature,re.MULTILINE)
    signed_team=re.search(r"^TeamIdentifier=(.+)$",signature,re.MULTILINE)
    if not signed_id or signed_id.group(1).strip()!=identifier or not signed_team or signed_team.group(1).strip()!=team_id:
        raise RuntimeError(f"Final code signature metadata mismatch for {identifier}: {signature[-1800:]}")

def main():
    if len(sys.argv) not in (3,4): raise SystemExit("usage: apple_sign_ipa.py INPUT.ipa OUTPUT.ipa [adhoc|development]")
    mode=(sys.argv[3] if len(sys.argv)==4 else env("SIGNING_MODE","adhoc")).lower()
    if mode not in ("adhoc","development"):
        raise RuntimeError("SIGNING_MODE must be either 'adhoc' or 'development'.")
    certificate_type="IOS_DEVELOPMENT" if mode=="development" else "IOS_DISTRIBUTION"
    profile_type="IOS_APP_DEVELOPMENT" if mode=="development" else "IOS_APP_ADHOC"
    expected_get_task_allow=(mode=="development")
    print(f"Signing mode: {mode} ({certificate_type}, {profile_type})")
    source,out=Path(sys.argv[1]).resolve(),Path(sys.argv[2]).resolve()
    if not source.is_file(): raise RuntimeError("Input IPA does not exist: "+str(source))
    work=Path("apple-signing-work").resolve(); work.mkdir(parents=True,exist_ok=True)
    apple=Apple()
    devices=apple.devices()
    enabled=[d for d in devices if d.get("attributes",{}).get("status")=="ENABLED"]
    if not enabled: raise RuntimeError("No ENABLED iOS devices registered with this Apple team.")
    if len(enabled)>100: raise RuntimeError(f"Found {len(enabled)} enabled iOS devices; Ad Hoc profiles support at most 100.")
    print(f"Including all {len(enabled)} enabled registered iOS devices; no UDID input is needed.")
    unpack=work/"unpacked"; unpack.mkdir(exist_ok=True)
    run("ditto","-x","-k",str(source),str(unpack))
    payload=unpack/"Payload"; roots=list(payload.glob("*.app"))
    if len(roots)!=1: raise RuntimeError(f"Expected one Payload/*.app, found {len(roots)}.")
    root=roots[0]
    bundles=[p for p in root.rglob("*") if p.is_dir() and p.suffix in (".app",".appex")]+[root]
    bundles=sorted(set(bundles),key=lambda p:len(p.parts),reverse=True)

    # The .tling suffix creates team-specific explicit identifiers even when
    # the source IPA uses upstream Chromium bundle IDs.
    identifiers=[bid(bundle) for bundle in bundles]
    if len(set(identifiers)) != len(identifiers):
        raise RuntimeError("The source IPA contains duplicate app/extension bundle identifiers.")

    # Namespace the containing app once, then preserve that prefix for every
    # embedded executable bundle. App extension IDs must begin with the
    # containing app's bundle ID; appending ".tling" independently to each
    # original ID breaks that required parent/extension relationship.
    root_info=plistlib.loads((root/"Info.plist").read_bytes())
    root_original=root_info.get("CFBundleIdentifier")
    if not root_original:
        raise RuntimeError("Main app is missing CFBundleIdentifier.")
    # Normalize any number of previously appended suffixes to exactly one.
    # This makes re-signing an already processed IPA idempotent and repairs
    # artifacts produced by older runs that appended the namespace repeatedly.
    root_base=re.sub(r"(?:\.tling)+$", "", root_original)
    if not root_base:
        raise RuntimeError(f"Cannot derive a valid base bundle identifier from {root_original!r}.")
    root_updated=root_base+".tling"
    if root_updated != root_original:
        print(f"Normalized main app bundle identifier: {root_original} -> {root_updated}")
    rewritten={}
    for bundle in bundles:
        info=bundle/"Info.plist"
        metadata=plistlib.loads(info.read_bytes())
        original=metadata.get("CFBundleIdentifier")
        if not original:
            raise RuntimeError("Missing CFBundleIdentifier: "+str(bundle))
        if bundle == root:
            updated=root_updated
        elif original.startswith(root_original+"."):
            child_suffix=original[len(root_original):]
            # Older versions appended .tling independently to each extension.
            # Remove that trailing marker while retaining the extension name.
            child_suffix=re.sub(r"(?:\\.tling)+$", "", child_suffix)
            updated=root_updated+child_suffix
        else:
            raise RuntimeError(
                f"Embedded executable bundle {original!r} is not inside the main app "
                f"bundle-ID namespace {root_original!r}; refusing to produce an invalid IPA."
            )
        if updated in rewritten.values():
            raise RuntimeError("Bundle ID rewriting produced a duplicate identifier: "+updated)
        metadata["CFBundleIdentifier"]=updated
        # Update companion-bundle references if present, before signing.
        def rewrite_references(value):
            if isinstance(value,dict):
                return {k:rewrite_references(v) for k,v in value.items()}
            if isinstance(value,list):
                return [rewrite_references(v) for v in value]
            if isinstance(value,str):
                if value == root_original:
                    return root_updated
                if value.startswith(root_original+"."):
                    child_suffix=value[len(root_original):]
                    child_suffix=re.sub(r"(?:\\.tling)+$", "", child_suffix)
                    return root_updated+child_suffix
            return value
        metadata=rewrite_references(metadata)
        info.write_bytes(plistlib.dumps(metadata,fmt=plistlib.FMT_XML,sort_keys=True))
        rewritten[original]=updated
        print(f"Rewrote bundle identifier: {original} -> {updated}")

    identifiers=[bid(bundle) for bundle in bundles]
    if any(not identifier.startswith(root_updated) for identifier in identifiers):
        raise RuntimeError("Internal error: an embedded executable bundle is outside the rewritten main app bundle-ID namespace.")

    # Provisioning starts only after the IPA's IDs pass the ownership check
    # and all bundle identifiers have been rewritten.
    p12,pw,cert_id=signing_cert(apple,work,certificate_type)

    # Import only after signing_cert has returned a real P12 and password.
    # Keep keychain creation after IPA ownership validation as well, so a
    # rejected upstream IPA never leaves an unnecessary signing identity.
    keychain=Path(env("RUNNER_TEMP","/tmp"))/"chromium-auto-sign.keychain-db"
    kp=secrets.token_urlsafe(24)
    run("security","create-keychain","-p",kp,str(keychain))
    run("security","set-keychain-settings","-lut","21600",str(keychain))
    run("security","unlock-keychain","-p",kp,str(keychain))
    run("security","import",str(p12),"-k",str(keychain),"-P",pw,"-T","/usr/bin/codesign","-T","/usr/bin/security")
    run("security","set-key-partition-list","-S","apple-tool:,apple:","-s","-k",kp,str(keychain))
    run("security","list-keychains","-d","user","-s",str(keychain))
    ident=run("security","find-identity","-v","-p","codesigning",str(keychain),capture=True)
    m=re.search(r"([0-9A-F]{40})",ident)
    if not m: raise RuntimeError("Imported P12 is not a valid Apple code-signing identity.")
    identity=m.group(1)
    # Read the Apple Team ID from the actual signing certificate, not from the profile.
    cert_file=work/"signing-cert.pem"
    run("openssl","pkcs12","-in",str(p12),"-clcerts","-nokeys","-passin","pass:"+pw,"-out",str(cert_file))
    subject=run("openssl","x509","-in",str(cert_file),"-noout","-subject",capture=True)
    team_match=re.search(r"OU\s*=\s*([A-Z0-9]+)",subject)
    team_id=team_match.group(1) if team_match else env("APPLE_TEAM_ID")
    if not team_id:
        raise RuntimeError("Could not determine Apple Team ID from the signing certificate.")

    profile_dir=work/"profiles"; profile_dir.mkdir(exist_ok=True)
    for bundle in bundles:
        identifier=bid(bundle); app_id=apple.appid(identifier)
        apple.ensure_capability(app_id,"APP_GROUPS")
        if bundle == root or identifier.endswith(".CredentialProviderExtension"):
            apple.ensure_capability(app_id,"AUTOFILL_CREDENTIAL_PROVIDER")
        filename=re.sub(r"[^A-Za-z0-9_.-]","_",identifier)+".mobileprovision"
        profile=profile_dir/filename
        profile_label="Development" if mode=="development" else "Ad Hoc"
        data=apple.profile("Chromium "+profile_label+" "+identifier,app_id,cert_id,[d["id"] for d in enabled],profile,profile_type)
        print(f"Created {profile_label} profile for {identifier} ({data.get('id')}).")
    # Sign every actual Mach-O executable/library before signing containing
    # frameworks, extensions, and the main app. Gecko ships bare Mach-O files
    # such as Frameworks/XUL which have no .dylib or .framework suffix; an
    # extension-based scan silently skipped them and caused dyld to reject XUL.
    macho_files=[p for p in root.rglob("*") if is_macho(p)]
    if not macho_files:
        raise RuntimeError("No Mach-O code was found inside the app; refusing to emit an unsigned IPA.")
    print(f"Found {len(macho_files)} Mach-O code file(s) by file type.")
    for p in sorted(macho_files,key=lambda x:len(x.parts),reverse=True):
        run("codesign","--force","--sign",identity,"--timestamp=none",str(p))
        print("Signed Mach-O:",p.relative_to(root))

    # Frameworks are bundles, so sign them after their inner Mach-O files.
    frameworks=sorted(
        (p for p in root.rglob("*.framework") if p.is_dir()),
        key=lambda x:len(x.parts),reverse=True
    )
    for framework in frameworks:
        run("codesign","--force","--sign",identity,"--timestamp=none",str(framework))
        run("codesign","--verify","--strict","--verbose=2",str(framework))

    # Provisioned .appex/.app bundles are signed last, deepest first, with the
    # exact entitlements authorized by their matching Ad Hoc profiles.
    for bundle in bundles:
        profile=profile_dir/(re.sub(r"[^A-Za-z0-9_.-]","_",bid(bundle))+".mobileprovision")
        sign_bundle(bundle,profile,identity,work,{d.get('attributes',{}).get('udid') for d in enabled},team_id,expected_get_task_allow)

    # Verify each Mach-O independently after its containing bundles have been
    # signed, then verify the complete app seal recursively.
    for p in macho_files:
        run("codesign","--verify","--strict","--verbose=2",str(p))
    run("codesign","--verify","--deep","--strict","--verbose=2",str(root))
    out.parent.mkdir(parents=True,exist_ok=True)
    if out.exists(): out.unlink()
    run("ditto","-c","-k","--sequesterRsrc","--keepParent",str(payload),str(out))
    print(run("shasum","-a","256",str(out),capture=True).strip())
    print(f"{mode.capitalize()} IPA signed and verified. {len(macho_files)} Mach-O file(s), {len(frameworks)} framework(s), {len(bundles)} app/extension bundle(s), {len(enabled)} registered enabled devices.")
    print("If App Group warnings appeared, register group.com.tling0001.chrome and group.com.tling0001.common in Certificates, Identifiers & Profiles, then assign both groups to every Chromium app/extension App ID before relying on cross-extension sharing.")

if __name__=="__main__":
    try: main()
    except subprocess.CalledProcessError as e:
        print(f"::error::Signing command failed: {e}",file=sys.stderr); raise
    except Exception as e:
        print(f"::error::{e}",file=sys.stderr); raise
