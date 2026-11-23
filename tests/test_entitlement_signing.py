import importlib.util
import pathlib
import unittest

MODULE_PATH = pathlib.Path(__file__).parents[1] / "scripts" / "apple_sign_ipa.py"
SPEC = importlib.util.spec_from_file_location("apple_sign_ipa", MODULE_PATH)
signer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(signer)


class EntitlementSigningTests(unittest.TestCase):
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

    def test_app_id_names_use_bundle_display_names_without_project_prefix(self):
        self.assertEqual(signer.sanitize_app_id_name("Libby", "com.overdrive.mobile"), "Libby")
        self.assertEqual(
            signer.sanitize_app_id_name("Libby Share Extension", "com.overdrive.mobile.share"),
            "Libby Share Extension",
        )
        self.assertEqual(signer.sanitize_app_id_name("", "com.example.Reader"), "Reader")

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

    def test_missing_profile_grant_fails_instead_of_dropping_entitlement(self):
        with self.assertRaisesRegex(RuntimeError, "not authorized"):
            signer.build_signing_entitlements(
                {"com.apple.developer.kernel.increased-memory-limit": True},
                {
                    "application-identifier": "NEWTEAM.com.example.app",
                    "com.apple.developer.team-identifier": "NEWTEAM",
                    "get-task-allow": True,
                },
                "com.example.app",
                "NEWTEAM",
                True,
            )


if __name__ == "__main__":
    unittest.main()
