"""
Tests for receipt/fiscal-day signing, QR codes, certificate renewal and tax ID lookup.

The receipt hash test uses the worked example from ZIMRA's Fiscal Device Gateway API
specification v7.2, section 13.2.1 (CreditNote, Example No 2), whose published hash is
F9/QB0vhxQlEF2nk+oebwP8V+qBcNlOFvoTeE/1QxPc=
"""
import base64
import hashlib
import inspect
import os
import sys
import tempfile
import unittest
from collections import OrderedDict
from datetime import date, datetime
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import zimra
from zimra import Device

PREVIOUS_HASH = "hNVJXP/ACOiE8McD3pKsDlqBXpuaUqQOfPnMyfZWI9k="


def sha256_b64(text):
    return base64.b64encode(hashlib.sha256(text.encode('utf-8')).digest()).decode('utf-8')


class DeviceTestCase(unittest.TestCase):
    """Creates a Device backed by a throwaway RSA key (no network)."""

    device_id = "322"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.key_path = os.path.join(self.tmp.name, "key.pem")
        with open(self.key_path, "wb") as f:
            f.write(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            ))
        self.cert_path = os.path.join(self.tmp.name, "cert.pem")
        self.device = Device(
            device_id=self.device_id,
            serialNo="SN-TEST",
            activationKey="00000000",
            cert_path=self.cert_path,
            private_key_path=self.key_path,
            test_mode=True,
            company_name="TestCo",
        )

    def tearDown(self):
        self.tmp.cleanup()


class TestReceiptSignature(DeviceTestCase):

    def test_credit_note_hash_matches_zimra_spec_example(self):
        receipt = OrderedDict([
            ("receiptType", "CreditNote"),
            ("receiptCurrency", "USD"),
            ("receiptGlobalNo", 85),
            ("receiptDate", "2020-09-19T09:23:07"),
            ("receiptTotal", -40.35),
            ("receiptTaxes", [
                {"taxID": 1, "taxAmount": 0, "salesAmountWithTax": -7.00},
                {"taxID": 2, "taxPercent": 0, "taxAmount": 0, "salesAmountWithTax": -10.00},
                {"taxID": 3, "taxPercent": 14.5, "taxAmount": -3.00, "salesAmountWithTax": -23.00},
            ]),
        ])
        signed = self.device.insert_receiptDeviceSignature(receipt, previous_hash=PREVIOUS_HASH)
        self.assertEqual(
            signed["receiptDeviceSignature"]["hash"],
            "F9/QB0vhxQlEF2nk+oebwP8V+qBcNlOFvoTeE/1QxPc=",
        )
        self.assertTrue(signed["receiptDeviceSignature"]["signature"])


class TestFiscalDaySignature(DeviceTestCase):

    def _close_day(self, counters):
        response = MagicMock()
        response.json.return_value = {"operationID": "test"}
        response.raise_for_status.return_value = None
        with patch.object(zimra.requests, "post", return_value=response) as post:
            self.device.closeDay(
                fiscalDayNo=84,
                fiscalDayDate="2019-09-23",
                lastReceiptCounterValue=3,
                fiscalDayCounters=counters,
            )
        payload = post.call_args.kwargs["json"]
        self.assertEqual(post.call_args.kwargs["timeout"], zimra.REQUEST_TIMEOUT)
        return payload["fiscalDayDeviceSignature"]["hash"]

    def test_all_money_types_are_signed_not_only_cash_and_card(self):
        counters = [
            {"fiscalCounterType": "BalanceByMoneyType", "fiscalCounterCurrency": "USD",
             "fiscalCounterMoneyType": "BankTransfer", "fiscalCounterValue": 5.00},
            {"fiscalCounterType": "BalanceByMoneyType", "fiscalCounterCurrency": "USD",
             "fiscalCounterMoneyType": 2, "fiscalCounterValue": 12.50},
        ]
        expected = "322842019-09-23" \
                   "BALANCEBYMONEYTYPEUSDMOBILEWALLET1250" \
                   "BALANCEBYMONEYTYPEUSDBANKTRANSFER500"
        self.assertEqual(self._close_day(counters), sha256_b64(expected))

    def test_cash_sorts_before_card_as_in_zimra_spec_example(self):
        # ZIMRA's example (section 13.3.1) lists ...ZWLCASH... before ...ZWLCARD...,
        # i.e. money types in enum order, whether given as names or as indexes.
        counters = [
            {"fiscalCounterType": "BalanceByMoneyType", "fiscalCounterCurrency": "ZWL",
             "fiscalCounterMoneyType": "Card", "fiscalCounterValue": 15000.00},
            {"fiscalCounterType": "BalanceByMoneyType", "fiscalCounterCurrency": "ZWL",
             "fiscalCounterMoneyType": 0, "fiscalCounterValue": 20000.00},
            {"fiscalCounterType": "SaleByTax", "fiscalCounterCurrency": "ZWL",
             "fiscalCounterTaxID": 3, "fiscalCounterTaxPercent": 15, "fiscalCounterValue": 12.00},
        ]
        expected = "322842019-09-23" \
                   "SALEBYTAXZWL15.001200" \
                   "BALANCEBYMONEYTYPEZWLCASH2000000" \
                   "BALANCEBYMONEYTYPEZWLCARD1500000"
        self.assertEqual(self._close_day(counters), sha256_b64(expected))


class TestQrCode(DeviceTestCase):

    def test_default_date_is_not_frozen_at_import(self):
        default = inspect.signature(Device.generate_qr_code).parameters["receipt_date"].default
        self.assertIsNone(default)
        signature = base64.b64encode(b"\x01" * 256).decode()
        qr = self.device.generate_qr_code(signature, 1)
        self.assertIn(datetime.now().strftime("%d%m%Y"), qr)

    def test_qr_layout(self):
        raw = b"\x02" * 256
        signature = base64.b64encode(raw).decode()
        qr = self.device.generate_qr_code(signature, 1332, receipt_date=date(2023, 4, 4))
        expected = self.device.qrUrl + "0000000322" + "04042023" + "0000001332" \
            + hashlib.md5(raw).hexdigest()[:16]
        self.assertEqual(qr, expected)


class TestRenewCertificate(DeviceTestCase):

    def test_saves_and_returns_new_certificate(self):
        response = MagicMock()
        response.json.return_value = {"certificate": "-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----"}
        response.raise_for_status.return_value = None
        cwd = os.getcwd()
        os.chdir(self.tmp.name)
        try:
            with patch.object(zimra.requests, "post", return_value=response):
                result = self.device.renewCertificate()
            self.assertEqual(result, response.json.return_value["certificate"])
            with open(os.path.join(self.tmp.name, "TestCo.crt")) as f:
                self.assertEqual(f.read(), result)
        finally:
            os.chdir(cwd)


class TestLegacyFifteenPercent(DeviceTestCase):

    def _receipt(self, tax_percent):
        return {
            "receiptType": "FiscalInvoice",
            "receiptCurrency": "USD",
            "receiptCounter": 1,
            "receiptGlobalNo": 1,
            "invoiceNo": "INV-1",
            "receiptDate": "2026-01-05T10:00:00",
            "receiptLines": [{"item_name": "Item", "tax_percent": tax_percent,
                              "quantity": 1, "unit_price": 10.00, "hs_code": "12345678"}],
            "receiptPayments": [{"moneyTypeCode": "Cash", "paymentAmount": 10.00}],
        }

    def test_15_percent_without_a_15_percent_tax_is_rejected(self):
        # Previously this silently used the 15.5% taxID with taxPercent 15 (RCPT025, Red).
        with self.assertRaises(ValueError):
            self.device.prepareReceipt(self._receipt(15))

    def test_15_percent_still_works_when_configured(self):
        self.device.applicableTaxes = {0: 2, 'exempt': 3, 15: 3, 15.5: 515}
        prepared = self.device.prepareReceipt(self._receipt(15))
        self.assertEqual(prepared["receiptLines"][0]["taxID"], 3)

    def test_15_5_percent_unchanged(self):
        prepared = self.device.prepareReceipt(self._receipt(15.5))
        self.assertEqual(prepared["receiptLines"][0]["taxID"], 515)


if __name__ == "__main__":
    unittest.main()
