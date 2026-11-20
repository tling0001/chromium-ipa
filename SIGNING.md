# Apple API credentials and automated device registration

The repository uses a **Team API Key** to call Apple's App Store Connect API. The private key is never written to the repository or uploaded as an artifact.

## Required repository secrets

Under **Settings → Secrets and variables → Actions**, configure:

- `APPLE_API_KEY_P8`: entire contents of the downloaded `.p8` file, including the BEGIN/END PRIVATE KEY lines.
- `APPLE_API_KEY_ID`: the key ID shown in App Store Connect.
- `APPLE_API_ISSUER_ID`: the issuer ID shown in App Store Connect.

Use a **Team API Key** with the **Admin** role. Individual API keys cannot access Apple's provisioning endpoints.

## Register devices

1. Open **Actions → Register Apple Devices for Chromium**.
2. Choose **Run workflow**.
3. Paste one or more iPhone/iPad UDIDs into `device_udids`. Separate them with commas, spaces, or new lines. Leave it blank to only list existing devices.
4. Run the workflow.

The workflow checks the team's registered iOS devices first, registers only UDIDs that are not already present, then refreshes the list and reports all devices with status `ENABLED`. It does not disable or remove existing devices.

New registrations may not be immediately eligible for provisioning. Apple says registrations 11–100 can take 24–72 hours to become eligible. Devices with a status other than `ENABLED` are reported separately.

The workflow uploads a short-lived `apple-registered-ios-devices` report artifact. Treat the UDIDs in that report as private.

## Signing status

This workflow implements the Apple API authentication and device-registration stage. It does **not** yet create signing certificates, App IDs, provisioning profiles, or a signed IPA. The existing `Sign Chromium iOS IPA` workflow still uses the older manually exported certificate/profile secrets; do not run it expecting the three Apple API secrets to work there yet.

Before automating final signing, the workflow must verify that Apple will issue a profile carrying Chromium's required `com.apple.developer.kernel.extended-virtual-addressing` entitlement and any other entitlements required by the exact app bundle and extensions. A paid membership and a valid API key do not by themselves grant an entitlement.
