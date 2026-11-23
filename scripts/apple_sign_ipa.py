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
# Only capabilities explicitly represented by Apple's public App Store Connect API
# are auto-enabled. Entitlements outside this map may be managed/approval-only.
ENTITLEMENT_CAPABILITIES = {
    "aps-environment": "PUSH_NOTIFICATIONS",
    "com.apple.developer.associated-domains": "ASSOCIATED_DOMAINS",
    "com.apple.security.application-groups": "APP_GROUPS",
    "com.apple.developer.healthkit": "HEALTHKIT",
    "com.apple.developer.default-data-protection": "DATA_PROTECTION",
    "com.apple.developer.game-center": "GAME_CENTER",
    "com.apple.developer.pass-type-identifiers": "WALLET",
    "com.apple.external-accessory.wireless-configuration": "WIRELESS_ACCESSORY_CONFIGURATION",
    "com.apple.developer.networking.vpn.api": "PERSONAL_VPN",
    "com.apple.developer.networking.HotspotConfiguration": "HOT_SPOT",
    "com.apple.developer.networking.wifi-info": "ACCESS_WIFI_INFORMATION",
    "com.apple.developer.networking.custom-protocol": "NETWORK_CUSTOM_PROTOCOL",
    "inter-app-audio": "INTER_APP_AUDIO",
    "com.apple.developer.homekit": "HOMEKIT",
    "com.apple.developer.siri": "SIRIKIT",
    "com.apple.developer.classkit-environment": "CLASSKIT",
    "com.apple.developer.networking.networkextension": "NETWORK_EXTENSIONS",
    "com.apple.developer.networking.multipath": "MULTIPATH",
    "com.apple.developer.nfc.readersession.formats": "NFC_TAG_READING",
    "com.apple.developer.applesignin": "APPLE_ID_AUTH",
    "com.apple.developer.icloud-container-identifiers": "ICLOUD",
    "com.apple.developer.ubiquity-container-identifiers": "ICLOUD",
    "com.apple.developer.in-app-payments": "APPLE_PAY",
    "com.apple.developer.authentication-services.autofill-credential-provider": "AUTOFILL_CREDENTIAL_PROVIDER",
}

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
    def appid(self,bid,display_name):
        for x in self.pages("/bundleIds?filter[identifier]="+quote(bid,safe="")+"&filter[platform]=IOS&limit=200"):
            if x.get("attributes",{}).get("identifier")==bid: return x["id"]
        # Apple App ID names are stricter than bundle identifiers: use the
        # app/extension's own display name, not the source project name.
        display_name=sanitize_app_id_name(display_name,bid)
        x=self.req("POST","/bundleIds",json={"data":{"type":"bundleIds","attributes":{"identifier":bid,"name":display_name,"platform":"IOS"}}})
        print(f"Created App ID: {bid} (name: {display_name})"); return x["data"]["id"]
    def ensure_capability(self,bundle_id_id,capability,identifier):
        # Apple-managed capabilities must be requested by the Account Holder
        # in the Developer portal before they can be enabled. The API reports
        # these as forbidden; skip them so unrelated signing work can continue.
        current=self.pages(f"/bundleIds/{bundle_id_id}/bundleIdCapabilities")
        if any(x.get("attributes",{}).get("capabilityType")==capability for x in current):
            print(f"Capability already enabled: {capability}")
            return True
        try:
            self.req("POST","/bundleIdCapabilities",json={"data":{"type":"bundleIdCapabilities","attributes":{"capabilityType":capability},"relationships":{"bundleId":{"data":{"type":"bundleIds","id":bundle_id_id}}}}})
        except RuntimeError as error:
            detail=str(error)
            if "HTTP 403" in detail or "HTTP 409" in detail:
                print(f"::warning::Skipping {capability} for {identifier}: Apple rejected automatic enablement ({detail}). If this is a managed capability, the Account Holder must request/obtain approval in Certificates, Identifiers & Profiles → Capability Requests, then enable it under Capabilities. Signing will continue without this entitlement if the profile does not authorize it.")
                return False
            raise
        print(f"Enabled capability: {capability}")
        return True
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

def _load_entitlement_plist(raw):
    try:
        value=plistlib.loads(raw)
    except Exception:
        return None
    if isinstance(value,dict) and isinstance(value.get("Entitlements"),dict):
        value=value["Entitlements"]
    return value if isinstance(value,dict) else None

def read_source_entitlements(bundle):
    """Read entitlements from the IPA's existing signature or packaged build metadata."""
    command=subprocess.run(
        ["codesign","-d","--entitlements",":-","--xml",str(bundle)],
        stdout=subprocess.PIPE,stderr=subprocess.PIPE
    )
    for stream in (command.stdout,command.stderr):
        parsed=_load_entitlement_plist(stream)
        if parsed is not None:
            keys=", ".join(sorted(parsed))
            print(f"Read {len(parsed)} source entitlement(s) from signature: {bundle.name}: {keys}")
            return parsed
    candidates=[]
    for pattern in ("*.entitlements","*.xcent","archived-expanded-entitlements.xcent"):
        for path in bundle.rglob(pattern):
            if not path.is_file():
                continue
            # A parent .app must not consume an embedded extension's
            # entitlements; each executable bundle is inspected separately.
            nested_bundle=any(parent != bundle and parent.suffix in (".app",".appex") for parent in path.parents)
            if not nested_bundle:
                candidates.append(path)
    parsed_candidates=[]
    for path in sorted(set(candidates)):
        try:
            parsed=_load_entitlement_plist(path.read_bytes())
        except OSError:
            parsed=None
        if parsed is not None:
            parsed_candidates.append((path,parsed))
    if len(parsed_candidates)>1:
        first=parsed_candidates[0][1]
        if any(value != first for _,value in parsed_candidates[1:]):
            names=", ".join(str(path.relative_to(bundle)) for path,_ in parsed_candidates)
            raise RuntimeError(f"Conflicting packaged entitlement files in {bundle}: {names}")
    if parsed_candidates:
        path,parsed=parsed_candidates[0]
        keys=", ".join(sorted(parsed))
        print(f"Read {len(parsed)} source entitlement(s) from packaged metadata: {path.relative_to(bundle)}: {keys}")
        return parsed
    print(f"::notice::No source entitlements were present in {bundle.name}. This IPA does not carry enough metadata to infer its original Xcode entitlements; only capabilities already assigned to the App ID can appear in the generated profile.")
    return {}

def capabilities_for_entitlements(entitlements):
    return sorted({capability for key,capability in ENTITLEMENT_CAPABILITIES.items() if key in entitlements})

def display_name_for_bundle(bundle):
    """Return a human-facing App ID name from the bundle's own metadata."""
    info=plistlib.loads((bundle/"Info.plist").read_bytes())
    candidates=(info.get("CFBundleDisplayName"),info.get("CFBundleName"),info.get("CFBundleExecutable"))
    for candidate in candidates:
        if isinstance(candidate,str) and candidate.strip():
            return candidate.strip()
    return bid(bundle).rsplit(".",1)[-1]

def sanitize_app_id_name(display_name,identifier):
    fallback=identifier.rsplit(".",1)[-1]
    sanitized=re.sub(r"[^A-Za-z0-9 ]+", " ", display_name or fallback)
    return " ".join(sanitized.split())[:100] or fallback[:100]

def _profile_value_allows(allowed, requested):
    """Check the profile allowlist, including Apple's string wildcards."""
    if isinstance(requested,str):
        if not isinstance(allowed,str):
            return False
        if allowed == requested:
            return True
        return allowed.endswith("*") and requested.startswith(allowed[:-1])
    if isinstance(requested,bool) or requested is None or isinstance(requested,(int,float)):
        return type(allowed) is type(requested) and allowed == requested
    if isinstance(requested,list):
        if not isinstance(allowed,list):
            return False
        return all(any(_profile_value_allows(candidate,item) for candidate in allowed) for item in requested)
    if isinstance(requested,dict):
        if not isinstance(allowed,dict):
            return False
        return all(key in allowed and _profile_value_allows(allowed[key],value) for key,value in requested.items())
    return False

def _rewrite_entitlement_value(value, old_prefix, new_prefix):
    if isinstance(value,str):
        value=value.replace("$(AppIdentifierPrefix)",new_prefix+".")
        value=value.replace("$(TeamIdentifierPrefix)",new_prefix+".")
        if old_prefix and value.startswith(old_prefix+"."):
            value=new_prefix+value[len(old_prefix):]
        return value
    if isinstance(value,list):
        return [_rewrite_entitlement_value(item,old_prefix,new_prefix) for item in value]
    if isinstance(value,dict):
        return {key:_rewrite_entitlement_value(item,old_prefix,new_prefix) for key,item in value.items()}
    return value

def build_signing_entitlements(requested, allowed, identifier, team_id, expected_get_task_allow, skipped_entitlements=None):
    """Claim authorized source entitlements; omit capabilities Apple requires the team to request."""
    skipped_entitlements=skipped_entitlements or set()
    app_identifier=allowed.get("application-identifier","")
    prefix=app_identifier.split(".",1)[0]
    if not prefix:
        raise RuntimeError(f"Provisioning profile for {identifier} has no application-identifier.")
    source_app_id=requested.get("application-identifier","")
    source_prefix=source_app_id.split(".",1)[0] if isinstance(source_app_id,str) else ""
    if not source_prefix:
        source_team=requested.get("com.apple.developer.team-identifier","")
        source_prefix=source_team if isinstance(source_team,str) else ""
    result={}
    for key,value in requested.items():
        if key in ("application-identifier","com.apple.developer.team-identifier","get-task-allow"):
            continue
        if key in skipped_entitlements:
            print(f"::warning::Omitting {key} from {identifier}: Apple did not authorize its managed capability for this App ID. The related app feature may be unavailable until the Account Holder requests/receives approval and a new profile is generated.")
            continue
        normalized=_rewrite_entitlement_value(value,source_prefix,prefix)
        # APNs uses a signing-mode-specific environment; the generated profile
        # is authoritative for whether this is development or production.
        if key == "aps-environment" and isinstance(allowed.get(key),str):
            normalized=allowed[key]
        if key not in allowed or not _profile_value_allows(allowed[key],normalized):
            raise RuntimeError(
                f"Required source entitlement {key!r}={normalized!r} for {identifier} "
                "is not authorized by its generated provisioning profile. Enable/request "
                "the capability for this App ID (or obtain Apple's approval for a managed entitlement), "
                "then rerun signing. The signer will not silently drop it."
            )
        result[key]=normalized
    result["application-identifier"]=prefix+"."+identifier
    result["com.apple.developer.team-identifier"]=team_id
    result["get-task-allow"]=expected_get_task_allow
    return result

def profile_plist(path,work):
    raw=run("security","cms","-D","-i",str(path),capture=True)
    return plistlib.loads(raw.encode())

def sign_bundle(bundle,profile,identity,work,enabled_udids,team_id,expected_get_task_allow,source_entitlements,skipped_entitlements=None):
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
    ent=build_signing_entitlements(source_entitlements,allowed,identifier,team_id,expected_get_task_allow,skipped_entitlements)
    if allowed.get(EVA) is not True:
        print(f"::warning::Profile for {identifier} does not authorize {EVA}; signature will be valid only for allowed entitlements and the known startup crash may remain.")
    if identifier.startswith("com.tling0001.chrome"):
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

    # Capture source app/extension entitlement requests before rewriting IDs
    # or replacing any existing signatures.
    source_entitlements_by_original={bid(bundle):read_source_entitlements(bundle) for bundle in bundles}
    display_names_by_original={bid(bundle):display_name_for_bundle(bundle) for bundle in bundles}

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
    is_chromium=root_base.startswith("com.tling0001.chrome")
    is_reynard=(root_base=="com.minh-ton.Reynard")
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
            child_suffix=re.sub(r"(?:\.tling)+$", "", child_suffix)
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
                    child_suffix=re.sub(r"(?:\.tling)+$", "", child_suffix)
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
    source_entitlements_by_updated={rewritten[original]:values for original,values in source_entitlements_by_original.items()}
    display_names_by_updated={rewritten[original]:value for original,value in display_names_by_original.items()}
    skipped_entitlements_by_bundle={}
    for bundle in bundles:
        identifier=bid(bundle); app_id=apple.appid(identifier,display_names_by_updated.get(identifier,identifier.rsplit(".",1)[-1]))
        requested=source_entitlements_by_updated.get(identifier,{})
        if is_reynard and bundle == root and "com.apple.developer.kernel.increased-memory-limit" not in requested:
            # Reynard's upstream 0.22.x build declares this requirement in its
            # target configuration, but its --no-signing IPA may omit the
            # expanded entitlement plist. Preserve the known requirement.
            requested=dict(requested)
            requested["com.apple.developer.kernel.increased-memory-limit"]=True
            source_entitlements_by_updated[identifier]=requested
            print("::notice::Added Reynard's documented increased-memory-limit entitlement requirement because the unsigned source IPA did not carry entitlement metadata.")
        detected_capabilities=capabilities_for_entitlements(requested)
        if detected_capabilities:
            capability_list=", ".join(detected_capabilities)
            print(f"Entitlement capability requests for {identifier}: {capability_list}")
        skipped_capabilities=set()
        for capability in detected_capabilities:
            if not apple.ensure_capability(app_id,capability,identifier):
                skipped_capabilities.add(capability)
        skipped_entitlements_by_bundle[identifier]={
            key for key,capability in ENTITLEMENT_CAPABILITIES.items()
            if key in requested and capability in skipped_capabilities
        }
        # Preserve the known Chromium integrations even when an upstream
        # unsigned IPA omitted its original entitlement metadata.
        if is_chromium:
            if not apple.ensure_capability(app_id,"APP_GROUPS",identifier):
                skipped_entitlements_by_bundle.setdefault(identifier,set()).add("com.apple.security.application-groups")
            if bundle == root or identifier.endswith(".CredentialProviderExtension"):
                if not apple.ensure_capability(app_id,"AUTOFILL_CREDENTIAL_PROVIDER",identifier):
                    skipped_entitlements_by_bundle.setdefault(identifier,set()).add("com.apple.developer.authentication-services.autofill-credential-provider")
        unmapped=sorted(key for key in requested if key not in ENTITLEMENT_CAPABILITIES and key not in {
            "application-identifier","com.apple.developer.team-identifier","get-task-allow",
            "keychain-access-groups"
        })
        for key in unmapped:
            print(f"::notice::Source entitlement {key!r} has no automatic App Store Connect capability mapping. The profile will be checked for authorization; managed/custom entitlements may require prior Apple approval or manual portal configuration.")
        filename=re.sub(r"[^A-Za-z0-9_.-]","_",identifier)+".mobileprovision"
        profile=profile_dir/filename
        profile_label="Development" if mode=="development" else "Ad Hoc"
        app_name=display_names_by_updated.get(identifier,identifier.rsplit(".",1)[-1])
        data=apple.profile(app_name+" "+profile_label,app_id,cert_id,[d["id"] for d in enabled],profile,profile_type)
        print(f"Created {profile_label} profile for {identifier} ({data.get('id')}).")
        if is_reynard and bundle == root:
            profile_entitlements=profile_plist(profile,work).get("Entitlements",{})
            if profile_entitlements.get("com.apple.developer.kernel.increased-memory-limit") is not True:
                print("::warning::The Reynard profile does not authorize com.apple.developer.kernel.increased-memory-limit. Because this is a required entitlement, signing will stop rather than emit an IPA that silently drops the increased-memory allowance.")
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
        identifier=bid(bundle)
        sign_bundle(bundle,profile,identity,work,{d.get('attributes',{}).get('udid') for d in enabled},team_id,expected_get_task_allow,source_entitlements_by_updated.get(identifier,{}),skipped_entitlements_by_bundle.get(identifier,set()))

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
    if is_chromium:
        print("If App Group warnings appeared, register group.com.tling0001.chrome and group.com.tling0001.common in Certificates, Identifiers & Profiles, then assign both groups to every Chromium app/extension App ID before relying on cross-extension sharing.")

if __name__=="__main__":
    try: main()
    except subprocess.CalledProcessError as e:
        print(f"::error::Signing command failed: {e}",file=sys.stderr); raise
    except Exception as e:
        print(f"::error::{e}",file=sys.stderr); raise
