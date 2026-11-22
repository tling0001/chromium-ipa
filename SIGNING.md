# Automated Chromium iOS Ad Hoc signing

The **Sign Chromium iOS IPA** workflow uses an App Store Connect Team API key to create Apple signing assets and sign the unsigned WebKit or Blink IPA. It does not require manually exported certificate or provisioning-profile files.

## Required repository secrets

Under **Settings → Secrets and variables → Actions**, configure:

- APPLE_API_KEY_P8: entire contents of the downloaded Team API .p8 file, including the BEGIN/END PRIVATE KEY lines.
- APPLE_API_KEY_ID: the API key ID.
- APPLE_API_ISSUER_ID: the issuer ID.
- GH_SECRETS_TOKEN: a fine-grained GitHub personal access token limited to this repository, with Secrets: read and write permission.

The Apple API key must be a **Team API Key** with the **Admin** role. Individual API keys do not support provisioning operations.

### Why GH_SECRETS_TOKEN is needed

The first signing run creates an Apple iOS Distribution certificate and a private key on the macOS runner. The workflow encrypts the P12 and its password using GitHub's repository-secret public key, then saves them as two additional encrypted repository secrets:

- APPLE_AUTO_SIGNING_P12_BASE64
- APPLE_AUTO_SIGNING_P12_PASSWORD

For **Development** signing, the workflow stores a separate identity in:

- APPLE_AUTO_SIGNING_DEV_P12_BASE64
- APPLE_AUTO_SIGNING_DEV_P12_PASSWORD

The first Development signing run also needs GH_SECRETS_TOKEN so it can save that identity. The development identity is kept separate from the existing distribution identity; selecting Development will not replace or revoke the distribution certificate.
The workflow's built-in GITHUB_TOKEN cannot write repository secrets. It saves the matching identity secrets for whichever signing mode is selected. GH_SECRETS_TOKEN is a separate, least-privilege credential used only during the first run to save the generated signing identity. Once both APPLE_AUTO_SIGNING_P12_BASE64 and APPLE_AUTO_SIGNING_P12_PASSWORD have been created, you can delete GH_SECRETS_TOKEN from repository secrets and revoke the fine-grained token. Subsequent runs reuse the saved certificate rather than creating another one and consuming Apple's limited distribution-certificate slots.

Create the GitHub token at https://github.com/settings/personal-access-tokens/new. Choose **Fine-grained token**, select only the tling0001/chromium-ipa repository, and grant **Secrets: Read and write**. Add the token as GH_SECRETS_TOKEN. Do not paste it into chat or commit it.

## Bundle IDs and App Groups

The build now uses the account-specific prefix com.tling0001 instead of Google's org.chromium prefix. This avoids attempting to register Chromium's original Google-owned identifiers under your Apple team.

The signing workflow automatically appends `.tling` to every app and extension Bundle ID in the IPA before registering those explicit identifiers with App Store Connect. It updates each bundle's `Info.plist` and then signs using the matching suffixed identifiers. For example, `com.tling0001.chrome.ios.dev` becomes `com.tling0001.chrome.ios.dev.tling`. It then enables the App Groups capability, and enables AutoFill Credential Provider for the main app and Credential Provider extension. Reprocessing an IPA that already has one or more trailing `.tling` suffixes now normalizes the main app ID to exactly one suffix and rewrites embedded app/extension IDs under that normalized namespace.

The separate **Publish IPA as Ad Hoc Release** workflow accepts a direct HTTPS IPA URL, rewrites and signs the app using the same Apple signing setup, then creates a GitHub release. The release title and IPA asset name use `<bundle-id> - <app-version>`; it also uploads `manifest.plist` and places an `itms-services://` installation link in the release description. This workflow expects the same Apple API and signing secrets described above.

**One Apple Developer portal step remains for App Groups:** Apple's public App Store Connect API can turn on APP_GROUPS but does not expose the App Group container registration and assignment operations. After the first signing run creates the Bundle IDs, open Certificates, Identifiers & Profiles:

1. Register these two App Groups:
   - group.com.tling0001.chrome
   - group.com.tling0001.common
2. For every Chromium App ID created by the signing workflow, edit the App ID, enable App Groups, and assign both groups.
3. Save the changes, then run the signing workflow again so its new Ad Hoc profiles include the group entitlements.

Apple documents App Groups and the required assignment process here: https://developer.apple.com/help/account/identifiers/enable-app-capabilities/

## Run signing

1. Open **Actions → Sign Chromium iOS IPA**.
2. Click **Run workflow**.
3. Choose WebKit or Blink and select the latest successful build, a run ID, or a direct IPA URL.
4. Choose **Ad Hoc** for the existing distribution-certificate flow, or **Development** to use an Apple Development certificate and an `IOS_APP_DEVELOPMENT` profile. Use Development for apps whose maintainers explicitly disallow distribution-certificate signing, such as Reynard.
5. The workflow automatically lists every ENABLED iOS device registered to your Apple Developer team. It does not need a UDID input for devices already registered.
6. It creates or reuses the certificate and profile type for the selected mode, registers explicit App IDs for the app and embedded app extensions, provisions all enabled registered devices, signs nested code and app bundles, verifies signatures, and uploads the signed IPA artifact. The signer identifies Mach-O binaries using the macOS `file` utility rather than filename extensions, so extensionless Gecko binaries such as `Frameworks/XUL` are included. It signs Mach-O files first, then framework bundles, then provisioned app/extension bundles, and verifies nested code plus the final app seal.

You do not need to run **Register Apple Devices for Chromium** if your devices are already registered. That separate workflow is optional for registering additional devices or inspecting the device list.

## Choosing a signing mode

The default **Ad Hoc** mode uses an `IOS_DISTRIBUTION` certificate and `IOS_APP_ADHOC` profiles with `get-task-allow=false`. **Development** mode uses an `IOS_DEVELOPMENT` certificate and `IOS_APP_DEVELOPMENT` profiles with `get-task-allow=true`. Each mode has its own saved P12 secrets and reuses only certificates of its own type.

Reynard's upstream README explicitly says distribution-certificate sideloading is unsupported. For Reynard, select **Development** rather than Ad Hoc. This aligns the signing identity with the installation method its maintainers support (AltStore/SideStore-style development signing), but does not guarantee compatibility with every third-party installer or custom bundle-ID rewrite.

## Publishing workflow safety

The **Publish IPA as Ad Hoc Release** workflow is manual-only. It requires an explicit HTTPS IPA URL and no longer runs automatically when the signing script or workflow changes. This prevents a code change from unintentionally re-signing and publishing the workflow's former default input IPA.

## Important entitlement limitation

Chromium's known PartitionAlloc startup crash is associated with com.apple.developer.kernel.extended-virtual-addressing. Apple's public App Store Connect API CapabilityType enum does not list Extended Virtual Addressing, so this workflow cannot enable it through the documented API. The signing script checks each generated profile and warns if the profile does not authorize this entitlement. It signs only with entitlements Apple's profile authorizes; it never fabricates a provisioning-profile grant.

Therefore, a successfully signed Ad Hoc IPA is not proof that the earlier startup crash is fixed. If the profile lacks Extended Virtual Addressing, the app may still crash on launch.

After the first run creates the main App ID, open **Certificates, Identifiers & Profiles → Identifiers → com.tling0001.chrome.ios.dev → Capability Requests**. If Extended Virtual Addressing is offered there, submit the request as Account Holder. If Apple approves it, enable the capability for the main App ID in the Capabilities tab, then rerun signing. The signing helper will detect whether the resulting provisioning profile includes the entitlement. If the capability is not offered in Capability Requests, contact Apple Developer Support and ask whether this entitlement can be assigned to your team for an iOS app using PartitionAlloc.

Apple documents managed-capability approval and profile behavior here: https://developer.apple.com/help/account/reference/provisioning-with-managed-capabilities/

Apple also documents the entitlement and provisioning-profile allowlist model:

- https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.kernel.extended-virtual-addressing
- https://developer.apple.com/documentation/appstoreconnectapi/capabilitytype
- https://developer.apple.com/documentation/technotes/tn3125-inside-code-signing-provisioning-profiles

## Notes

- Ad Hoc profiles are for direct installation on registered devices, including installation through Sideloadly.
- Apple permits up to 100 registered iOS devices per membership year; only ENABLED devices are included.
- The signing workflow does not remove, disable, or revoke any registered device or existing certificate.
- Profiles are generated for each .app and .appex bundle identifier discovered inside the IPA.
- The Apple API key is exposed only to the signing step, not to the IPA download step.
