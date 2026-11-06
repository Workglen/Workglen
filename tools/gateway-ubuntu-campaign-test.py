#!/usr/bin/env python3
"""Focused tests for the guarded Ubuntu campaign's pure helpers."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("gateway-ubuntu-campaign.py")
SPEC = importlib.util.spec_from_file_location("gateway_ubuntu_campaign", SCRIPT)
assert SPEC and SPEC.loader
CAMPAIGN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CAMPAIGN)


class CampaignHelpers(unittest.TestCase):
    def test_message_counts_are_bounded(self) -> None:
        self.assertEqual(CAMPAIGN.parse_counts("100,10000,100000"), [100, 10000, 100000])
        for value in ("99", "100001", "100,nope"):
            with self.assertRaises(Exception):
                CAMPAIGN.parse_counts(value)

    def test_addresses_must_use_reserved_domains(self) -> None:
        CAMPAIGN.test_address("owner@example.test", "recipient")
        CAMPAIGN.test_address("sender@example.invalid", "sender")
        with self.assertRaises(RuntimeError):
            CAMPAIGN.test_address("owner@example.com", "recipient")

    def test_text_profile_is_exactly_sized(self) -> None:
        payload = CAMPAIGN.message(
            0, 4096, "sender@example.invalid", "owner@example.test", "unit", "text"
        )
        self.assertEqual(len(payload), 4096)
        self.assertIn(b"X-Workglen-Campaign-Profile: text\r\n", payload)

    def test_mixed_profile_is_deterministic_complete_and_exactly_sized(self) -> None:
        payloads = [
            CAMPAIGN.message(
                index,
                4096,
                "sender@example.invalid",
                "owner@example.test",
                "unit",
                "mixed",
            )
            for index in range(len(CAMPAIGN.MIXED_MESSAGE_VARIANTS))
        ]
        self.assertTrue(all(len(payload) == 4096 for payload in payloads))
        for variant, payload in zip(CAMPAIGN.MIXED_MESSAGE_VARIANTS, payloads):
            self.assertIn(f"X-Workglen-Campaign-Profile: {variant}\r\n".encode(), payload)
        self.assertIn(b"Content-Type: application/gzip", payloads[2])
        self.assertIn(b"Content-Type: message/rfc822", payloads[3])
        self.assertIn(b"deliberately-invalid-base64", payloads[4])

    def test_profile_refuses_a_target_smaller_than_its_mime_structure(self) -> None:
        with self.assertRaises(RuntimeError):
            CAMPAIGN.message(
                1, 256, "sender@example.invalid", "owner@example.test", "unit", "mixed"
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
