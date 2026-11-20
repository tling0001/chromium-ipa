# Automated Chromium iOS Ad Hoc signing

The **Sign Chromium iOS IPA** workflow uses an App Store Connect Team API key to create Apple signing assets and sign the unsigned WebKit or Blink IPA. It does not require manually exported certificate or provisioning-profile files.

## Required repository secrets

Under **Settings → Secrets and variables → Actions**, configure:

- APPLE_API_KEY_P8: entire contents of the downloaded Team API .p8 file, including the BEGIN/END PRIVATE KEY lines.
- APPLE_API_KEY_ID: the API key ID.
- APPLE_API_ISSUER_ID: the issuer ID.
- GH_SECRETS_TOKEN: a fine-grained GitHub personal access token limited to this repository, with **Secrets: read and write** (write is required; read is useful for verification).

The Apple API key must be a **Team API Key** with the **Admin** role. Individual API keys do not support provisioning operations.

### Why GH_SECRETS_TOKEN is needed

The first signing run creates an Apple iOS Distribution certificate and a private key on the macOS runner. The workflow encrypts the P12 and its password using GitHub's repository-secret public key, then saves them as two additional encrypted repository secrets:

- APPLE_AUTO_SIGNING_P12_BASE64
- APPLE_AUTO_SIGNING_P12_PASSWORD

The workflow's built-in GITHUB_TOKEN cannot write repository secrets. GH_SECRETS_TOKEN is a separate, least-privilege credential used only to save the generated signing identity. Subsequent runs reuse that certificate rather than creating another one and consuming Apple's limited distribution-certificate slots.

Create the GitHub token at https://github.com/settings/personal-access-tokens/new. Choose **Fine-grained token**, select only the tling0001/chromium-ipa repository, and grant **Secrets: Read and write**. Add the token as GH_SECRETS_TOKEN. Do not paste it into chat or commit it.

## Run signing

1. Open **Actions → Sign Chromium iOS IPA**.
2. Click **Run workflow**.
3. Choose WebKit or Blink and select the latest successful build, a run ID, or a direct IPA URL.
4. The workflow automatically lists every ENABLED iOS device registered to your Apple Developer team. It does not need a UDID input for devices already registered.
5. It creates or reuses the Apple distribution certificate, registers explicit App IDs for the app and embedded app extensions, creates Ad Hoc profiles containing all enabled registered devices, signs nested code and app bundles, verifies signatures, and uploads the signed IPA artifact.

You do not need to run **Register Apple Devices for Chromium** if your devices are already registered. That separate workflow is optional for registering additional devices or inspecting the device list.

## Important entitlement limitation

Chromium's known PartitionAlloc startup crash is associated with com.apple.developer.kernel.extended-virtual-addressing. Apple's public App Store Connect API CapabilityType enum does not list Extended Virtual Addressing, so this workflow cannot enable it through the documented API. The signing script checks each generated profile and warns if the profile does not authorize this entitlement. It signs only with entitlements Apple's profile authorizes; it never fabricates a provisioning-profile grant.

Therefore, a successfully signed Ad Hoc IPA is not proof that the earlier startup crash is fixed. If the profile lacks Extended Virtual Addressing, the app may still crash on launch. Apple documents the entitlement and the provisioning-profile allowlist model:

- https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.kernel.extended-virtual-addressing
- https://developer.apple.com/documentation/appstoreconnectapi/capabilitytype
- https://developer.apple.com/documentation/technotes/tn3125-inside-code-signing-provisioning-profiles

## Notes

- Ad Hoc profiles are for direct installation on registered devices, including installation through Sideloadly.
- Apple permits up to 100 registered iOS devices per membership year; only ENABLED devices are included.
- The signing workflow does not remove, disable, or revoke any registered device or existing certificate.
- Profiles are generated for each .app and .appex bundle identifier discovered inside the IPA.
- The Apple API key is exposed only to the signing step, not to the IPA download step.
