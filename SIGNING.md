# Signing an iOS Chromium IPA

The **Sign Chromium iOS IPA** workflow is a manual, separate workflow. It does not rebuild Chromium or change the unsigned build workflow.

## Required GitHub Actions secrets

Create these under **Settings → Secrets and variables → Actions → Repository secrets**:

- `APPLE_CERTIFICATE_P12_BASE64`: Base64-encoded Apple iOS Development signing certificate, including its private key, exported as a password-protected `.p12`.
- `APPLE_CERTIFICATE_PASSWORD`: Password used when exporting that `.p12`.
- `IOS_PROVISIONING_PROFILES_ZIP_BASE64`: Base64-encoded ZIP containing the `.mobileprovision` profiles for the app and every embedded app extension.

The signing identity and provisioning profiles must belong to the same Apple Developer team. The profiles must be valid for the device(s) on which you intend to install the app and must authorize the entitlements used by their respective bundles.

### Prepare the secrets on macOS

Export the iOS Development certificate **with its private key** from Keychain Access as a password-protected `.p12`. Then base64-encode it:

```sh
base64 -i ios-signing-certificate.p12 | tr -d '\n'
```

Put the output in `APPLE_CERTIFICATE_P12_BASE64`.

Put the export password in `APPLE_CERTIFICATE_PASSWORD`.

Put all required provisioning profiles in one ZIP. Chromium's current iOS build instructions list these app identifiers (with the configured bundle prefix):

- `<prefix>.chrome.ios.dev` (main app)
- `<prefix>.chrome.ios.dev.CredentialProviderExtension`
- `<prefix>.chrome.ios.dev.IntentsExtension`
- `<prefix>.chrome.ios.dev.OpenExtension`
- `<prefix>.chrome.ios.dev.ShareExtension`
- `<prefix>.chrome.ios.dev.WidgetKitExtension`

The main app profile must authorize `com.apple.developer.kernel.extended-virtual-addressing=true`. Chromium's instructions also call out App Groups `group.<prefix>.chrome` and `group.<prefix>.common`; the main app and extensions need the capabilities they actually use. The main app and Credential Provider extension also need the AutoFill Credential Provider entitlement.

ZIP the profile files (the ZIP can contain subdirectories), then encode it:

```sh
base64 -i ios-provisioning-profiles.zip | tr -d '\n'
```

Put that output in `IOS_PROVISIONING_PROFILES_ZIP_BASE64`.

**Important:** the workflow deliberately stops if the main app's provisioning profile does not itself authorize extended virtual addressing. Adding the entitlement to the app's signed entitlements cannot grant a capability that Apple's profile does not authorize.

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
