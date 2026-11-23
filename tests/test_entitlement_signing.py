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
