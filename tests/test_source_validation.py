import socket
import unittest

from kubit.source_validation import (
    FetchResponse,
    SourceValidationBusy,
    SourceValidationError,
    SourceValidator,
)


def resolver_for(mapping):
    def resolve(host, port, type):
        address = mapping[host]
        family = socket.AF_INET6 if ":" in address else socket.AF_INET
        sockaddr = (address, port, 0, 0) if family == socket.AF_INET6 else (address, port)
        return [(family, type, 6, "", sockaddr)]

    return resolve


class SourceValidatorTest(unittest.TestCase):
    def test_rejects_unsafe_url_shapes_before_dns(self):
        validator = SourceValidator(resolver=lambda *args, **kwargs: self.fail("DNS must not run"))
        invalid = [
            "http://example.org/matrix",
            "https://user:password@example.org/matrix",  # pragma: allowlist secret
            "https://example.org:8443/matrix",
            "https://127.0.0.1/matrix",
            "https://localhost/matrix",
            "https://example.org/matrix#section",
            "https://example.org/matrix?token=secret",
            "https://example.org\\@internal/matrix",
        ]
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(SourceValidationError):
                validator.validate("example", value)

    def test_rejects_private_dns_destination_without_connecting(self):
        validator = SourceValidator(
            resolver=resolver_for({"internal.example": "10.0.0.12"}),
            transport=lambda *args: self.fail("transport must not run"),
        )
        result = validator.validate("example", "https://internal.example/matrix")
        self.assertFalse(result["eligible"])
        self.assertIn("private", result["reason"])
        self.assertNotIn("validation_token", result)

    def test_redirect_destination_is_resolved_and_revalidated(self):
        validator = SourceValidator(
            resolver=resolver_for({
                "public.example": "93.184.216.34",
                "internal.example": "192.168.1.5",
            }),
            transport=lambda url, addresses: FetchResponse(
                302,
                {"location": "https://internal.example/secret"},
                b"",
            ),
        )
        result = validator.validate("example", "https://public.example/matrix")
        self.assertFalse(result["eligible"])
        self.assertIn("private", result["reason"])

    def test_html_meta_refresh_is_treated_as_a_validated_redirect(self):
        responses = {
            "https://docs.example/old": FetchResponse(
                200,
                {"content-type": "text/html"},
                b'<meta http-equiv="refresh" content="0; url=/matrix">',
            ),
            "https://docs.example/matrix": FetchResponse(
                200,
                {"content-type": "text/plain"},
                b"Example supports Kubernetes 1.31",
            ),
        }
        validator = SourceValidator(
            resolver=resolver_for({"docs.example": "93.184.216.34"}),
            transport=lambda url, addresses: responses[url],
        )
        result = validator.validate("example", "https://docs.example/old")
        self.assertTrue(result["eligible"])
        self.assertEqual(result["final_url"], "https://docs.example/matrix")
        self.assertEqual(result["redirects"][0]["status"], "meta-refresh")

    def test_relevant_public_content_is_eligible_and_ticket_is_single_use(self):
        clock = [1_000.0]
        validator = SourceValidator(
            resolver=resolver_for({"docs.example": "93.184.216.34"}),
            transport=lambda url, addresses: FetchResponse(
                200,
                {"content-type": "text/markdown; charset=utf-8"},
                b"# CloudNativePG\nSupported Kubernetes versions: v1.31 through v1.36",
            ),
            clock=lambda: clock[0],
        )
        result = validator.validate(
            "cloudnative-pg",
            "https://docs.example/support",
            {"docs.example"},
            actor_id=7,
        )
        self.assertTrue(result["eligible"])
        self.assertTrue(result["known_official_origin"])
        self.assertEqual(result["versions_detected"], ["1.31", "1.36"])
        component, url, validation = validator.consume(
            "cloudnative-pg", "https://docs.example/support", result["validation_token"], actor_id=7
        )
        self.assertEqual((component, url), ("cloudnative-pg", "https://docs.example/support"))
        self.assertNotIn("validation_token", validation)
        with self.assertRaises(SourceValidationError):
            validator.consume(
                "cloudnative-pg", "https://docs.example/support", result["validation_token"], actor_id=7
            )
        other = validator.validate(
            "cloudnative-pg",
            "https://docs.example/support",
            {"docs.example"},
            actor_id=7,
        )
        with self.assertRaisesRegex(SourceValidationError, "different operator"):
            validator.consume(
                "cloudnative-pg", "https://docs.example/support", other["validation_token"], actor_id=8
            )

    def test_ticket_expires_and_irrelevant_content_is_not_eligible(self):
        clock = [2_000.0]
        validator = SourceValidator(
            resolver=resolver_for({"docs.example": "93.184.216.34"}),
            transport=lambda url, addresses: FetchResponse(
                200,
                {"content-type": "text/plain"},
                b"CloudNativePG release notes without a platform matrix",
            ),
            clock=lambda: clock[0],
            ticket_ttl_seconds=10,
        )
        irrelevant = validator.validate("cloudnative-pg", "https://docs.example/notes")
        self.assertFalse(irrelevant["eligible"])
        self.assertNotIn("validation_token", irrelevant)

        validator.transport = lambda url, addresses: FetchResponse(
            200,
            {"content-type": "text/plain"},
            b"CloudNativePG supports Kubernetes 1.31",
        )
        eligible = validator.validate("cloudnative-pg", "https://docs.example/matrix")
        clock[0] += 11
        with self.assertRaises(SourceValidationError):
            validator.consume(
                "cloudnative-pg", "https://docs.example/matrix", eligible["validation_token"]
            )

    def test_operator_attempts_are_rate_limited(self):
        validator = SourceValidator(
            resolver=resolver_for({"docs.example": "93.184.216.34"}),
            transport=lambda url, addresses: FetchResponse(
                200,
                {"content-type": "text/plain"},
                b"Example supports Kubernetes 1.31",
            ),
            attempts_per_minute=1,
        )
        validator.validate("example", "https://docs.example/matrix", actor_id=9)
        with self.assertRaises(SourceValidationBusy):
            validator.validate("example", "https://docs.example/matrix", actor_id=9)


if __name__ == "__main__":
    unittest.main()
