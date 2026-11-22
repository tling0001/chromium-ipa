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
    def certs(self):
        # Do not request/require the undocumented "activated" field: the
        # Certificates API may omit it even for a valid current certificate.
        return self.pages("/certificates?filter[certificateType]=IOS_DISTRIBUTION&limit=200&fields[certificates]=certificateType,serialNumber,expirationDate")
    def create_cert(self,work):
        key=work/"dist.key"; csr=work/"dist.csr"
        run("openssl","genrsa","-out",str(key),"2048")
        run("openssl","req","-new","-key",str(key),"-out",str(csr),"-subj","/CN=Chromium iOS Ad Hoc Distribution")
        x=self.req("POST","/certificates",json={"data":{"type":"certificates","attributes":{"certificateType":"IOS_DISTRIBUTION","csrContent":csr.read_text()}}})["data"]
        der=work/"dist.cer"; der.write_bytes(base64.b64decode(x["attributes"]["certificateContent"]))
        cert=work/"dist.pem"; run("openssl","x509","-inform","DER","-in",str(der),"-out",str(cert))
        password=secrets.token_urlsafe(30); p12=work/"distribution.p12"
        run("openssl","pkcs12","-export","-inkey",str(key),"-in",str(cert),"-out",str(p12),"-passout","pass:"+password,"-name","Chromium iOS Ad Hoc")
        print("Created IOS_DISTRIBUTION certificate:",x["attributes"].get("serialNumber",""))
        return p12,password
    def profile(self,name,bid_id,cert_id,device_ids,path):
        # Replace only an existing profile with this exact generated name
        # and App ID. This avoids Apple's HTTP 409 duplicate-name response
        # while ensuring the replacement includes the current cert/devices.
        for existing in self.pages("/profiles?filter[profileType]=IOS_APP_ADHOC&limit=200"):
            if existing.get("attributes",{}).get("name") != name[:100]:
                continue
            pid=existing["id"]
            detail=self.req("GET",f"/profiles/{pid}?include=bundleId")
            rel=detail.get("data",{}).get("relationships",{}).get("bundleId",{}).get("data",{})
            if rel.get("id") != bid_id:
                continue
            print(f"Deleting duplicate Ad Hoc profile {pid} for {name}; it will be regenerated.")
            self.req("DELETE",f"/profiles/{pid}")
        body={"data":{"type":"profiles","attributes":{"name":name[:100],"profileType":"IOS_APP_ADHOC"},"relationships":{
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

def signing_cert(apple,work):
    b64,pw=env(P12_SECRET),env(PASS_SECRET)
    if bool(b64)!=bool(pw): raise RuntimeError("Both auto signing P12 secrets must exist together.")
    if b64:
        p12=work/"saved.p12"; p12.write_bytes(base64.b64decode(b64))
        run("openssl","pkcs12","-in",str(p12),"-passin","pass:"+pw,"-noout")
        serial=cert_serial(p12,pw,work)
        for c in apple.certs():
            a=c.get("attributes",{}); s=(a.get("serialNumber") or "").replace(":","").lstrip("0").upper() or "0"
            # Missing "activated" is not evidence of revocation. Only reject
            # an explicit false value; Apple exposes expiration separately.
            if s==serial and a.get("activated") is not False:
                print("Reusing saved Apple distribution certificate:", c["id"])
                return p12,pw,c["id"]
        print("Saved certificate was not found in Apple's current certificate list; checking before requesting another.")
    p12,pw=apple.create_cert(work); serial=cert_serial(p12,pw,work); found=None
    for c in apple.certs():
        a=c.get("attributes",{}); s=(a.get("serialNumber") or "").replace(":","").lstrip("0").upper() or "0"
        if s==serial: found=c; break
    if not found:
        raise RuntimeError("New Apple certificate was created but is not yet visible in the API. Retry signing; the saved P12 will be reused once Apple lists it.")
    gh_secret(P12_SECRET,base64.b64encode(p12.read_bytes()).decode())
    gh_secret(PASS_SECRET,pw)
    return p12,pw,found["id"]

def bid(bundle):
    x=plistlib.loads((bundle/"Info.plist").read_bytes()).get("CFBundleIdentifier")
    if not x: raise RuntimeError("Missing CFBundleIdentifier: "+str(bundle))
    return x

def profile_plist(path,work):
    raw=run("security","cms","-D","-i",str(path),capture=True)
    return plistlib.loads(raw.encode())

def sign_bundle(bundle,profile,identity,work,enabled_udids,team_id):
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
    if allowed.get("get-task-allow") is not False:
        raise RuntimeError(f"Provisioning profile for {identifier} does not explicitly disable get-task-allow.")
    certs=data.get("DeveloperCertificates",[])
    identity_sha1=identity.replace(" ","").upper()
    profile_cert_hashes={hashlib.sha1(cert).hexdigest().upper() for cert in certs}
    if identity_sha1 not in profile_cert_hashes:
        raise RuntimeError(f"Provisioning profile for {identifier} does not contain the distribution certificate used to sign it (SHA-1 {identity_sha1}).")
    ent=dict(allowed); ent["application-identifier"]=prefix+"."+identifier
    if "com.apple.developer.team-identifier" in ent: ent["com.apple.developer.team-identifier"]=prefix
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
    if len(sys.argv)!=3: raise SystemExit("usage: apple_sign_ipa.py INPUT.ipa OUTPUT.ipa")
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

    # Give every app/extension a team-specific suffix before registering
    # App IDs with Apple. The on-disk Info.plist identifiers must match the
    # identifiers used for provisioning and the final code signature.
    rewritten={}
    for bundle in bundles:
        info=bundle/"Info.plist"
        metadata=plistlib.loads(info.read_bytes())
        original=metadata.get("CFBundleIdentifier")
        if not original:
            raise RuntimeError("Missing CFBundleIdentifier: "+str(bundle))
        updated=original if original.endswith(".tling") else original+".tling"
        if updated in rewritten.values():
            raise RuntimeError("Bundle ID suffixing produced a duplicate identifier: "+updated)
        metadata["CFBundleIdentifier"]=updated
        info.write_bytes(plistlib.dumps(metadata,fmt=plistlib.FMT_XML,sort_keys=True))
        rewritten[original]=updated
        print(f"Rewrote bundle identifier: {original} -> {updated}")

    identifiers=[bid(bundle) for bundle in bundles]
    if any(not identifier.endswith(".tling") for identifier in identifiers):
        raise RuntimeError("Internal error: not all bundle identifiers end in .tling.")

    # Provisioning starts only after the IPA's IDs pass the ownership check
    # and all bundle identifiers have been rewritten.
    p12,pw,cert_id=signing_cert(apple,work)

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
    team_match=re.search(r"OU=([A-Z0-9]+)",subject)
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
        data=apple.profile("Chromium Ad Hoc "+identifier,app_id,cert_id,[d["id"] for d in enabled],profile)
        print(f"Created Ad Hoc profile for {identifier} ({data.get('id')}).")
    # Sign nested Mach-O code before extensions and the main application.
    code=[]
    for p in root.rglob("*"):
        if (p.is_dir() and p.suffix==".framework") or (p.is_file() and p.suffix==".dylib"): code.append(p)
    for p in sorted(code,key=lambda x:len(x.parts),reverse=True):
        run("codesign","--force","--sign",identity,"--timestamp=none",str(p))
    for bundle in bundles:
        profile=profile_dir/(re.sub(r"[^A-Za-z0-9_.-]","_",bid(bundle))+".mobileprovision")
        sign_bundle(bundle,profile,identity,work,{d.get('attributes',{}).get('udid') for d in enabled},team_id)
    run("codesign","--verify","--deep","--strict","--verbose=2",str(root))
    out.parent.mkdir(parents=True,exist_ok=True)
    if out.exists(): out.unlink()
    run("ditto","-c","-k","--sequesterRsrc","--keepParent",str(payload),str(out))
    print(run("shasum","-a","256",str(out),capture=True).strip())
    print(f"Ad Hoc IPA signed. {len(bundles)} app/extension bundle(s), {len(enabled)} registered enabled devices.")
    print("If App Group warnings appeared, register group.com.tling0001.chrome and group.com.tling0001.common in Certificates, Identifiers & Profiles, then assign both groups to every Chromium app/extension App ID before relying on cross-extension sharing.")

if __name__=="__main__":
    try: main()
    except subprocess.CalledProcessError as e:
        print(f"::error::Signing command failed: {e}",file=sys.stderr); raise
    except Exception as e:
        print(f"::error::{e}",file=sys.stderr); raise
