# Signing an iOS Chromium IPA

The **Sign Chromium iOS IPA** workflow is a manual, separate workflow. It does not rebuild Chromium or change the unsigned build workflow.

## Required GitHub Actions secrets

Create these under **Settings → Secrets and variables → Actions → Repository secrets**:

- `APPLE_CERTIFICATE_P12_BASE64`: Base64-encoded Apple iOS Development signing certificate, including its private key, exported as a password-protected `.p12`.
- `APPLE_CERTIFICATE_PASSWORD`: Password used when exporting that `.p12`.
- `IOS_PROVISIONING_PROFILES_ZIP_BASE64`: Base64-encoded ZIP containing the `.mobileprovision` profiles for the app and every embedded app extension.

The signing identity and provisioning profiles must belong to the same Apple Developer team. The profiles must be valid for the device(s) on which you intend to install the app and must authorize the entitlements used by their respective bundles.

### Prepare the secrets on Windows 11

You can prepare the Base64 secret values on Windows; no local Mac, Xcode, WSL, or OpenSSL is needed.

1. Export or obtain your Apple iOS signing certificate as a password-protected `.p12` **including its private key**. If you do not already have this file, see the limitation below.
2. Put the `.p12` file in a private folder.
3. Create a folder containing the `.mobileprovision` files for the Chromium main app and every embedded app extension.
4. Open PowerShell in the repository folder and run:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\scripts\prepare-signing-secrets.ps1 -P12Path "C:\Path\To\ios-signing-certificate.p12" -ProfilesFolder "C:\Path\To\ProvisioningProfiles"
```

The script creates `signing-secrets\APPLE_CERTIFICATE_P12_BASE64.txt` and `signing-secrets\IOS_PROVISIONING_PROFILES_ZIP_BASE64.txt`.

5. In GitHub, open **Settings → Secrets and variables → Actions → New repository secret**.
6. Create:
   - `APPLE_CERTIFICATE_P12_BASE64`: paste the entire contents of the first text file.
   - `APPLE_CERTIFICATE_PASSWORD`: enter the password used to export the P12.
   - `IOS_PROVISIONING_PROFILES_ZIP_BASE64`: paste the entire contents of the second text file.
7. Delete the local `signing-secrets` folder after GitHub has saved the secrets. Never commit these files.

The PowerShell helper is [`scripts/prepare-signing-secrets.ps1`](scripts/prepare-signing-secrets.ps1).

**Certificate limitation:** Windows can encode an existing P12 and package profiles, but it cannot create an Apple-authorized iOS signing identity merely by editing an IPA. You need a valid Apple-issued certificate with its private key and matching provisioning profiles. If you only have a free Apple ID and Sideloadly, you may not have the certificate/profile capability required for this entitlement.

**Entitlement limitation:** the main app's provisioning profile must explicitly authorize `com.apple.developer.kernel.extended-virtual-addressing=true`. The workflow checks this before signing. If the profile doesn't authorize it, the job stops; it cannot override Apple's provisioning restrictions.


## Run it

1. Open the repository's **Actions** tab.
2. Select **Sign Chromium iOS IPA**.
3. Click **Run workflow**.
4. Choose the source:
   - `latest_successful`: newest successful build run with the matching, unexpired WebKit/Blink artifact.
   - `run_id`: a specific build run ID.
   - `url`: a direct HTTPS URL to an IPA.
5. Choose WebKit or Blink when using a build artifact.
6. Download the resulting `chromium-ios-<variant>-signed` artifact from the signing run.

The direct URL must point to the IPA file itself, not a GitHub Actions artifact webpage.

## Notes

- The signing workflow uses a temporary macOS keychain and removes its signing files and keychain at the end of the job.
- Build artifacts expire according to the retention setting in the build workflow.
- A valid signature does not guarantee installation: bundle IDs, device registration, App Groups, extension profiles, and all required entitlements must match.
- Apple may restrict availability of particular capabilities for an account or App ID. The workflow cannot bypass Apple's provisioning rules.
