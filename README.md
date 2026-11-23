# Chromium IPA Release Library

This repository contains the iOS IPA signing automation and a searchable web catalog of published signed app releases.

## Deploy the catalog to Vercel

1. Import `tling0001/chromium-ipa` into [Vercel](https://vercel.com/new).
2. Choose **Other** as the framework preset (or leave the framework as **Other**).
3. Leave the build command and output directory empty. The site is a static `index.html` and requires no build step.
4. Deploy. Vercel will serve the catalog from the repository root.

The catalog reads public GitHub Releases from this repository directly in the browser. It does not require a database, environment variables, or a GitHub token.

## Release metadata

The publishing workflow extracts the app's display name, bundle identifier, and version from the signed IPA's top-level `Info.plist`. It adds those values and the selected signing mode to the GitHub release description. The catalog reads those fields and the release assets to build its searchable app entries.

For older releases that predate the app-name field, the catalog falls back to a readable name derived from the bundle identifier.

## Catalog features

- Search by app name, bundle identifier, version, or release description.
- Filter Development and Ad Hoc signing modes.
- View release notes, install instructions, IPA downloads, and OTA manifests.
- Browse other published versions of the same bundle identifier.
