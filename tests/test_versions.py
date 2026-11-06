import unittest

from kubit.versions import image_tag, parse


class VersionsTest(unittest.TestCase):
    def test_parses_kubernetes_and_talos_versions(self):
        self.assertEqual(parse("v1.35.9").series, "1.35")
        self.assertEqual(parse("Talos (v1.12.1)").patch, 1)

    def test_extracts_image_tag_without_confusing_registry_port(self):
        self.assertEqual(image_tag("registry.example:5000/cnpg/cloudnative-pg:1.30.2"), "1.30.2")
        self.assertEqual(image_tag("registry.example/app@sha256:abc"), "unknown")


if __name__ == "__main__":
    unittest.main()
