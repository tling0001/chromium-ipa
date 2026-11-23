import importlib.util
import pathlib
import unittest
from unittest import mock

MODULE_PATH = pathlib.Path(__file__).parents[1] / "scripts" / "apple_sign_ipa.py"
SPEC = importlib.util.spec_from_file_location("apple_sign_ipa", MODULE_PATH)
signer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(signer)


class EntitlementSigningTests(unittest.TestCase):
    def test_profile_reuses_newest_active_matching_profile(self):
        import base64
        import tempfile
        from datetime import datetime, timedelta, timezone

        class FakeApple(signer.Apple):
            def __init__(self):
                self.deleted = []
                self.posted = False
            def pages(self, path):
                return [
                    {"id": "older", "attributes": {"name": "Gboard Development [com.example.gboard.tling]"}},
                    {"id": "newer", "attributes": {"name": "Gboard Development [bundle-id]"}},
                ]
            def req(self, method, path, **kwargs):
                if method == "GET":
                    pid = path.split("/")[2].split("?")[0]
                    created = "2026-01-01T00:00:00Z" if pid == "older" else "2026-02-01T00:00:00Z"
                    return {"data": {
                        "id": pid,
                        "attributes": {
                            "createdDate": created,
                            "profileState": "ACTIVE",
                            "expirationDate": (datetime.now(timezone.utc) + timedelta(days=30)).isoformat(),
                            "profileContent": base64.b64encode(b"newest-profile" if pid == "newer" else b"older-profile").decode(),
                        },
                        "relationships": {
                            "bundleId": {"data": {"id": "bundle-id"}},
                            "certificates": {"data": [{"id": "cert-id"}]},
                            "devices": {"data": [{"id": "device-1"}, {"id": "device-2"}]},
                        },
                    }}
                if method == "DELETE":
                    self.deleted.append(path)
                    return {}
                if method == "POST":
                    self.posted = True
                    raise AssertionError("A matching active profile should be reused")
                raise AssertionError(method)

        apple = FakeApple()
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory) / "profile.mobileprovision"
            result = apple.profile(
                "Gboard Development", "bundle-id", "cert-id",
                ["device-1", "device-2"], output, "IOS_APP_DEVELOPMENT",
            )
            self.assertEqual(result["id"], "newer")
            self.assertEqual(output.read_bytes(), b"newest-profile")
            self.assertFalse(apple.posted)
            self.assertEqual(apple.deleted, [])

    def test_profile_name_is_scoped_to_bundle_identifier(self):
        import tempfile
        class FakeApple(signer.Apple):
            def __init__(self):
                self.payload = None
            def pages(self, path):
                return []
            def req(self, method, path, **kwargs):
                self.payload = kwargs["json"]
                return {"data": {"id": "profile-id", "attributes": {"profileContent": ""}}}

        apple = FakeApple()
        with tempfile.TemporaryDirectory() as directory:
            apple.profile("Gboard Development", "com.example.gboard.tling", "cert-id",
                          ["device-1"], pathlib.Path(directory) / "profile.mobileprovision",
                          "IOS_APP_DEVELOPMENT")
        self.assertEqual(
            apple.payload["data"]["attributes"]["name"],
            "Gboard Development [com.example.gboard.tling]",
        )

    def test_subprocess_capture_replaces_non_utf8_bytes(self):
        completed = mock.Mock(stdout="Mach-O executable �")
        with mock.patch.object(signer.subprocess, "run", return_value=completed) as run_mock:
            output = signer.run("file", "-b", "café", capture=True)
        self.assertEqual(output, "Mach-O executable �")
        self.assertEqual(run_mock.call_args.kwargs["encoding"], "utf-8")
        self.assertEqual(run_mock.call_args.kwargs["errors"], "replace")
        self.assertTrue(run_mock.call_args.kwargs["text"])

    def test_maps_supported_entitlements_to_capabilities(self):
        requested = {
            "aps-environment": "development",
            "com.apple.security.application-groups": ["group.example.shared"],
            "com.apple.developer.kernel.increased-memory-limit": True,
        }
        self.assertEqual(
            signer.capabilities_for_entitlements(requested),
            ["APP_GROUPS", "PUSH_NOTIFICATIONS"],
        )

    def test_reserved_apple_bundle_namespace_is_rewritten(self):
        self.assertEqual(
            signer.normalized_root_bundle_id("com.apple.AppStoreConnect"),
            "com.tling0001.AppStoreConnect.tling",
        )
        self.assertEqual(
            signer.normalized_root_bundle_id("com.apple.AppStoreConnect.tling"),
            "com.tling0001.AppStoreConnect.tling",
        )
        self.assertEqual(
            signer.normalized_root_bundle_id("com.example.Reader"),
            "com.example.Reader.tling",
        )

    def test_app_id_names_use_bundle_display_names_without_project_prefix(self):
        self.assertEqual(signer.sanitize_app_id_name("Libby", "com.overdrive.mobile"), "Libby")
        self.assertEqual(
            signer.sanitize_app_id_name("Libby Share Extension", "com.overdrive.mobile.share"),
            "Libby Share Extension",
        )
        self.assertEqual(signer.sanitize_app_id_name("", "com.example.Reader"), "Reader")

    def test_sign_in_with_apple_capability_uses_primary_app_configuration(self):
        class FakeApple(signer.Apple):
            def __init__(self):
                self.payload = None
            def pages(self, path):
                return []
            def req(self, method, path, **kwargs):
                self.payload = kwargs["json"]
                return {"data": {"id": "capability-id"}}

        apple = FakeApple()
        self.assertTrue(apple.ensure_capability("bundle-id-id", "APPLE_ID_AUTH", "com.example.app"))
        attributes = apple.payload["data"]["attributes"]
        self.assertEqual(attributes["capabilityType"], "APPLE_ID_AUTH")
        self.assertEqual(
            attributes["settings"],
            [{
                "key": "APPLE_ID_AUTH_APP_CONSENT",
                "options": [{"key": "PRIMARY_APP_CONSENT"}],
            }],
        )

    def test_icloud_capability_includes_required_cloudkit_version(self):
        class FakeApple(signer.Apple):
            def __init__(self):
                self.payload = None
            def pages(self, path):
                return []
            def req(self, method, path, **kwargs):
                self.payload = kwargs["json"]
                return {"data": {"id": "icloud-capability-id"}}

        apple = FakeApple()
        self.assertTrue(apple.ensure_capability("bundle-id-id", "ICLOUD", "com.example.app"))
        attributes = apple.payload["data"]["attributes"]
        self.assertEqual(attributes["capabilityType"], "ICLOUD")
        self.assertEqual(
            attributes["settings"],
            [{
                "key": "ICLOUD_VERSION",
                "options": [{"key": "XCODE_6", "enabled": True}],
            }],
        )

    def test_existing_icloud_capability_with_null_settings_is_repaired(self):
        class FakeApple(signer.Apple):
            def __init__(self):
                self.patch = None
            def pages(self, path):
                return [{
                    "id": "icloud-capability-id",
                    "attributes": {"capabilityType": "ICLOUD", "settings": None},
                }]
            def req(self, method, path, **kwargs):
                self.patch = (method, path, kwargs["json"])
                return {"data": {"id": "icloud-capability-id"}}

        apple = FakeApple()
        self.assertTrue(apple.ensure_capability("bundle-id-id", "ICLOUD", "com.example.app"))
        method, path, payload = apple.patch
        self.assertEqual(method, "PATCH")
        self.assertEqual(path, "/bundleIdCapabilities/icloud-capability-id")
        self.assertEqual(
            payload["data"]["attributes"]["settings"],
            [{
                "key": "ICLOUD_VERSION",
                "options": [{"key": "XCODE_6", "enabled": True}],
            }],
        )

    def test_managed_capability_request_errors_are_skipped(self):
        self.assertTrue(signer.is_managed_capability_request_error(
            RuntimeError("Apple API POST returned HTTP 403: forbidden")
        ))
        self.assertTrue(signer.is_managed_capability_request_error(
            RuntimeError("Apple API error: this capability must be requested")
        ))
        self.assertFalse(signer.is_managed_capability_request_error(
            RuntimeError("Apple API POST returned HTTP 500: internal server error")
        ))

    def test_skipped_managed_capability_is_not_claimed(self):
        requested = {
            "com.apple.developer.family-controls": True,
            "application-identifier": "OLDTEAM.com.example.app",
        }
        allowed = {
            "application-identifier": "NEWTEAM.com.example.app",
            "com.apple.developer.team-identifier": "NEWTEAM",
            "get-task-allow": True,
            "com.apple.developer.family-controls": True,
        }
        result = signer.build_signing_entitlements(
            requested,
            allowed,
            "com.example.app",
            "NEWTEAM",
            True,
            {"com.apple.developer.family-controls"},
        )
        self.assertNotIn("com.apple.developer.family-controls", result)
        self.assertEqual(result["application-identifier"], "NEWTEAM.com.example.app")

    def test_associated_domains_boolean_profile_grant_authorizes_domain_list(self):
        requested = {
            "com.apple.developer.associated-domains": [
                "applinks:libbyapp.com",
                "webcredentials:libbyapp.com",
            ],
        }
        allowed = {
            "application-identifier": "NEWTEAM.com.overdrive.dewey.tling",
            "com.apple.developer.team-identifier": "NEWTEAM",
            "get-task-allow": False,
            "com.apple.developer.associated-domains": True,
        }
        result = signer.build_signing_entitlements(
            requested, allowed, "com.overdrive.dewey.tling", "NEWTEAM", False
        )
        self.assertEqual(
            result["com.apple.developer.associated-domains"],
            ["applinks:libbyapp.com", "webcredentials:libbyapp.com"],
        )

    def test_associated_domains_filters_custom_url_schemes_and_ungranted_hosts(self):
        requested = {
            "com.apple.developer.associated-domains": [
                "applinks:example.com",
                "webcredentials:login.example.com",
                "sapphire://autoSuggest?query=cat",
                r"applinks:www\\.example.com",
            ],
        }
        allowed = {
            "application-identifier": "NEWTEAM.com.example.app",
            "com.apple.developer.team-identifier": "NEWTEAM",
            "get-task-allow": False,
            "com.apple.developer.associated-domains": [
                "applinks:example.com",
                "webcredentials:login.example.com",
            ],
        }
        result = signer.build_signing_entitlements(
            requested, allowed, "com.example.app", "NEWTEAM", False
        )
        self.assertEqual(
            result["com.apple.developer.associated-domains"],
            ["applinks:example.com", "webcredentials:login.example.com"],
        )

    def test_enabled_capability_does_not_reuse_profile_missing_entitlement(self):
        import base64
        import plistlib
        import tempfile
        from datetime import datetime, timedelta, timezone

        old_profile = base64.b64encode(plistlib.dumps({
            "Entitlements": {"application-identifier": "TEAM.com.example.app"}
        })).decode()
        new_profile = base64.b64encode(plistlib.dumps({
            "Entitlements": {
                "application-identifier": "TEAM.com.example.app",
                "com.apple.developer.associated-domains": True,
            }
        })).decode()

        class FakeApple(signer.Apple):
            def __init__(self):
                self.deleted = []
                self.posted = False
            def pages(self, path):
                return [{"id": "old-profile", "attributes": {"name": "App Ad Hoc [bundle-id]"}}]
            def req(self, method, path, **kwargs):
                if method == "GET":
                    return {"data": {
                        "id": "old-profile",
                        "attributes": {
                            "createdDate": "2026-01-01T00:00:00Z",
                            "profileState": "ACTIVE",
                            "expirationDate": (datetime.now(timezone.utc) + timedelta(days=30)).isoformat(),
                            "profileContent": old_profile,
                        },
                        "relationships": {
                            "bundleId": {"data": {"id": "bundle-id"}},
                            "certificates": {"data": [{"id": "cert-id"}]},
                            "devices": {"data": [{"id": "device-1"}]},
                        },
                    }}
                if method == "DELETE":
                    self.deleted.append(path)
                    return {}
                if method == "POST":
                    self.posted = True
                    return {"data": {"id": "new-profile", "attributes": {"profileContent": new_profile}}}
                raise AssertionError(method)

        apple = FakeApple()
        with tempfile.TemporaryDirectory() as directory:
            apple.profile(
                "App Ad Hoc", "bundle-id", "cert-id", ["device-1"],
                pathlib.Path(directory) / "profile.mobileprovision",
                "IOS_APP_ADHOC", ["com.apple.developer.associated-domains"],
            )
        self.assertEqual(apple.deleted, ["/profiles/old-profile"])
        self.assertTrue(apple.posted)

    def test_ungranted_associated_domains_are_dropped_without_failing(self):
        requested = {
            "com.apple.developer.associated-domains": [
                "applinks:libbyapp.com",
                "webcredentials:libbyapp.com",
            ],
        }
        allowed = {
            "application-identifier": "NEWTEAM.com.overdrive.dewey.tling",
            "com.apple.developer.team-identifier": "NEWTEAM",
            "get-task-allow": False,
        }
        result = signer.build_signing_entitlements(
            requested, allowed, "com.overdrive.dewey.tling", "NEWTEAM", False
        )
        self.assertNotIn("com.apple.developer.associated-domains", result)

    def test_profile_wildcard_authorizes_matching_string(self):
        self.assertTrue(signer._profile_value_allows("TEAM.example.*", "TEAM.example.app"))
        self.assertFalse(signer._profile_value_allows("TEAM.other.*", "TEAM.example.app"))

    def test_profile_array_is_allowlist_not_exact_match(self):
        self.assertTrue(
            signer._profile_value_allows(
                ["group.example.one", "group.example.two"],
                ["group.example.two"],
            )
        )
        self.assertFalse(
            signer._profile_value_allows(
                ["group.example.one"],
                ["group.example.two"],
            )
        )

    def test_only_requested_entitlements_are_claimed(self):
        requested = {
            "application-identifier": "OLDTEAM.com.example.app",
            "keychain-access-groups": ["OLDTEAM.com.example.app"],
            "com.apple.security.application-groups": ["group.example.shared"],
        }
        allowed = {
            "application-identifier": "NEWTEAM.com.example.app.tling",
            "com.apple.developer.team-identifier": "NEWTEAM",
            "get-task-allow": True,
            "keychain-access-groups": ["NEWTEAM.*"],
            "com.apple.security.application-groups": ["group.example.shared"],
            "com.apple.developer.healthkit": True,
        }
        result = signer.build_signing_entitlements(
            requested, allowed, "com.example.app.tling", "NEWTEAM", True
        )
        self.assertEqual(
            set(result),
            {
                "application-identifier",
                "com.apple.developer.team-identifier",
                "get-task-allow",
                "keychain-access-groups",
                "com.apple.security.application-groups",
            },
        )
        self.assertEqual(result["keychain-access-groups"], ["NEWTEAM.com.example.app"])

    def test_ungranted_carplay_audio_is_dropped_without_failing(self):
        requested = {"com.apple.developer.carplay-audio": True}
        allowed = {
            "application-identifier": "NEWTEAM.com.overdrive.dewey.tling",
            "com.apple.developer.team-identifier": "NEWTEAM",
            "get-task-allow": True,
        }
        result = signer.build_signing_entitlements(
            requested, allowed, "com.overdrive.dewey.tling", "NEWTEAM", True
        )
        self.assertNotIn("com.apple.developer.carplay-audio", result)

    def test_ungranted_increased_memory_entitlement_is_dropped_without_failing(self):
        requested = {"com.apple.developer.kernel.increased-memory-limit": True}
        allowed = {
            "application-identifier": "NEWTEAM.com.example.app",
            "com.apple.developer.team-identifier": "NEWTEAM",
            "get-task-allow": True,
        }
        result = signer.build_signing_entitlements(
            requested, allowed, "com.example.app", "NEWTEAM", True
        )
        self.assertNotIn("com.apple.developer.kernel.increased-memory-limit", result)


if __name__ == "__main__":
    unittest.main()
