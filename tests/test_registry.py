import unittest

from asa import registry


class TestListChecks(unittest.TestCase):
    def test_returns_entries_for_secrets_category(self):
        checks = registry.list_checks()
        secrets_checks = [c for c in checks if c["category"] == "secrets"]
        self.assertGreaterEqual(len(secrets_checks), 7)

    def test_filter_by_category(self):
        checks = registry.list_checks(category="secrets")
        self.assertTrue(all(c["category"] == "secrets" for c in checks))

    def test_filter_by_unknown_category_returns_empty(self):
        checks = registry.list_checks(category="not-a-real-category")
        self.assertEqual(checks, [])

    def test_every_check_has_required_fields(self):
        for c in registry.list_checks():
            self.assertIn("category", c)
            self.assertIn("check_id", c)
            self.assertIn("module", c)


class TestModulesFor(unittest.TestCase):
    def test_all_modules_when_no_category(self):
        self.assertGreaterEqual(len(registry.modules_for()), 1)

    def test_filtered_modules_match_category(self):
        mods = registry.modules_for("secrets")
        self.assertTrue(all(m.CATEGORY.value == "secrets" for m in mods))


class TestCheckerModulesAreValid(unittest.TestCase):
    def test_every_registered_module_has_the_contract(self):
        from asa.checkers import CHECKER_MODULES
        for mod in CHECKER_MODULES:
            self.assertTrue(hasattr(mod, "CATEGORY"))
            self.assertTrue(hasattr(mod, "CHECK_IDS"))
            self.assertTrue(callable(mod.activates))
            self.assertTrue(callable(mod.run))


if __name__ == "__main__":
    unittest.main()
