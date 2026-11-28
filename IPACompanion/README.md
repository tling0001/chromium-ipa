# IPA Library Companion (SwiftUI)

A native iOS/iPadOS companion catalog for releases published by the chromium-ipa repository.

- Browse and search the public release catalog.
- See app bundle IDs, versions, signing mode, release notes, and artwork.
- Launch OTA installation for Ad Hoc releases that include a manifest.
- Download IPA or open the GitHub release page.
- Build via GitHub Actions simulator build.

**Update limitation:** iOS does not expose a general API for listing other installed apps or silently installing/updating their binaries. OTA installation can update an existing app only when the signed app, device, and provisioning/signing conditions are compatible.

Build locally with XcodeGen: `xcodegen generate --spec IPACompanion/project.yml`, then open `IPACompanion.xcodeproj`.
