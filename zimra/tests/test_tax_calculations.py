"""
Comprehensive Unit Tests for ZIMRA Tax Calculations

This test module covers:
1. tax_calculator (standalone function) - VAT extraction from tax-inclusive prices
2. Device.tax_calculator (method) - VAT extraction from tax-inclusive prices  
3. Device.tax_exclusive_calculator (method) - VAT calculation for tax-exclusive prices

Test categories:
- Basic functionality tests
- Edge cases (zero amounts, zero rates)
- Precision and rounding tests
- Zimbabwe-specific tax rates (0%, 5%, 15%, 15.5%)
- Real-world business scenarios
- Floating point precision validation
"""

import unittest
import sys
import os
from decimal import Decimal, ROUND_HALF_UP
from unittest.mock import patch, MagicMock

# Add parent directory to path to import the zimra module
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from zimra import tax_calculator


class TestStandaloneTaxCalculator(unittest.TestCase):
    """Tests for the standalone tax_calculator function (tax-inclusive VAT extraction)."""
    
    # ==================== Basic Functionality Tests ====================
    
    def test_basic_15_percent_tax(self):
        """Test VAT extraction at 15% rate (legacy Zimbabwe standard rate)."""
        # $100 total, 15% VAT = $100 - ($100 / 1.15) = $100 - $86.96 = $13.04
        result = tax_calculator(100.00, 15)
        self.assertAlmostEqual(result, 13.04, places=2)
    
    def test_basic_15_5_percent_tax(self):
        """Test VAT extraction at 15.5% rate (2026 Zimbabwe standard rate)."""
        # $100 total, 15.5% VAT = $100 - ($100 / 1.155) = $100 - $86.58 = $13.42
        result = tax_calculator(100.00, 15.5)
        self.assertAlmostEqual(result, 13.42, places=2)
    
    def test_basic_5_percent_tax(self):
        """Test VAT extraction at 5% rate (Zimbabwe withholding tax)."""
        # $100 total, 5% VAT = $100 - ($100 / 1.05) = $100 - $95.24 = $4.76
        result = tax_calculator(100.00, 5)
        self.assertAlmostEqual(result, 4.76, places=2)
    
    def test_basic_20_percent_tax(self):
        """Test VAT extraction at 20% rate."""
        # $200 total, 20% VAT = $200 - ($200 / 1.20) = $200 - $166.67 = $33.33
        result = tax_calculator(200.00, 20)
        self.assertAlmostEqual(result, 33.33, places=2)
    
    # ==================== Edge Cases ====================
    
    def test_zero_amount(self):
        """Test VAT calculation with zero sale amount."""
        result = tax_calculator(0, 15)
        self.assertEqual(result, 0)
    
    def test_zero_tax_rate(self):
        """Test VAT calculation with zero tax rate (zero-rated goods)."""
        result = tax_calculator(100.00, 0)
        self.assertEqual(result, 0)
    
    def test_both_zero(self):
        """Test VAT calculation when both amount and rate are zero."""
        result = tax_calculator(0, 0)
        self.assertEqual(result, 0)
    
    def test_very_small_amount(self):
        """Test VAT calculation with very small amounts (penny-level)."""
        # $0.01 at 15%: result should be $0.00 (rounds to 0)
        result = tax_calculator(0.01, 15)
        self.assertAlmostEqual(result, 0.00, places=2)
    
    def test_small_amount_with_vat(self):
        """Test VAT calculation with small amounts that produce VAT."""
        # $0.50 at 15% = $0.07
        result = tax_calculator(0.50, 15)
        self.assertAlmostEqual(result, 0.07, places=2)
    
    def test_very_large_amount(self):
        """Test VAT calculation with large amounts."""
        # $1,000,000 at 15% = $130,434.78
        result = tax_calculator(1000000.00, 15)
        self.assertAlmostEqual(result, 130434.78, places=2)
    
    def test_negative_amount_should_work(self):
        """Test VAT calculation with negative amounts (for refunds/credit notes)."""
        result = tax_calculator(-100.00, 15)
        self.assertAlmostEqual(result, -13.04, places=2)
    
    # ==================== Precision and Rounding Tests ====================
    
    def test_rounding_half_up(self):
        """Test that rounding follows ROUND_HALF_UP convention."""
        # Find a case where rounding matters
        # $10.25 at 15.5% 
        result = tax_calculator(10.25, 15.5)
        expected = float(Decimal('10.25') - (Decimal('10.25') / Decimal('1.155')))
        expected_rounded = round(expected, 2)
        self.assertAlmostEqual(result, expected_rounded, places=2)
    
    def test_floating_point_precision(self):
        """Test that calculation avoids floating point errors."""
        # Classic floating point issue: 0.1 + 0.2 != 0.3 in pure floating point
        # Test with amounts that could cause float precision issues
        result = tax_calculator(123.45, 15.5)
        # Manual calculation: 123.45 - (123.45 / 1.155) = 123.45 - 106.88... = 16.57
        self.assertAlmostEqual(result, 16.57, places=2)
    
    def test_decimal_precision_consistency(self):
        """Test consistent 2-decimal place precision across different amounts."""
        test_cases = [
            (99.99, 15),
            (100.01, 15),
            (50.00, 15.5),
            (75.50, 5),
        ]
        for amount, rate in test_cases:
            with self.subTest(amount=amount, rate=rate):
                result = tax_calculator(amount, rate)
                # Ensure result has max 2 decimal places
                self.assertEqual(result, round(result, 2))
    
    # ==================== Zimbabwe-Specific Tax Rates ====================
    
    def test_zimbabwe_zero_rate(self):
        """Test zero-rated goods (0% VAT) - basic commodities."""
        result = tax_calculator(1000.00, 0)
        self.assertEqual(result, 0.0)
    
    def test_zimbabwe_5_percent_withholding(self):
        """Test 5% non-VAT withholding tax rate."""
        # $500 at 5% = $500 - ($500 / 1.05) = $500 - $476.19 = $23.81
        result = tax_calculator(500.00, 5)
        self.assertAlmostEqual(result, 23.81, places=2)
    
    def test_zimbabwe_15_percent_legacy(self):
        """Test legacy 15% standard VAT rate."""
        # $250 at 15% = $250 - ($250 / 1.15) = $250 - $217.39 = $32.61
        result = tax_calculator(250.00, 15)
        self.assertAlmostEqual(result, 32.61, places=2)
    
    def test_zimbabwe_15_5_percent_standard_2026(self):
        """Test 2026 standard 15.5% VAT rate."""
        # $250 at 15.5% = $250 - ($250 / 1.155) = $250 - $216.45 = $33.55
        result = tax_calculator(250.00, 15.5)
        self.assertAlmostEqual(result, 33.55, places=2)
    
    # ==================== Real-World Business Scenarios ====================
    
    def test_grocery_basket(self):
        """Test typical grocery basket amount."""
        # Customer pays $78.50 including 15.5% VAT
        result = tax_calculator(78.50, 15.5)
        expected = 10.53  # $78.50 - ($78.50 / 1.155)
        self.assertAlmostEqual(result, expected, places=2)
    
    def test_fuel_purchase(self):
        """Test fuel purchase scenario."""
        # $150 fuel at 15.5%
        result = tax_calculator(150.00, 15.5)
        expected = 20.13
        self.assertAlmostEqual(result, expected, places=2)
    
    def test_restaurant_bill(self):
        """Test restaurant bill scenario."""
        # $45.75 dinner bill at 15.5%
        result = tax_calculator(45.75, 15.5)
        expected = 6.14
        self.assertAlmostEqual(result, expected, places=2)
    
    def test_electronics_purchase(self):
        """Test electronics purchase (high value)."""
        # $2,500 laptop at 15.5%
        result = tax_calculator(2500.00, 15.5)
        expected = 335.50
        self.assertAlmostEqual(result, expected, places=2)
    
    def test_multiple_item_total(self):
        """Test calculation on a multi-item receipt total."""
        # 3 items: $10.00 + $25.50 + $14.50 = $50.00 at 15.5%
        total = 50.00
        result = tax_calculator(total, 15.5)
        expected = 6.71
        self.assertAlmostEqual(result, expected, places=2)
    
    # ==================== Decimal String Input Tests ====================
    
    def test_string_decimal_amount(self):
        """Test that string inputs are handled correctly."""
        result = tax_calculator("100.00", 15)
        self.assertAlmostEqual(result, 13.04, places=2)
    
    def test_string_decimal_rate(self):
        """Test that string tax rate is handled correctly."""
        result = tax_calculator(100.00, "15")
        self.assertAlmostEqual(result, 13.04, places=2)
    
    def test_both_string_inputs(self):
        """Test that both string inputs are handled correctly."""
        result = tax_calculator("100.00", "15.5")
        self.assertAlmostEqual(result, 13.42, places=2)


class TestDeviceTaxCalculator(unittest.TestCase):
    """Tests for the Device.tax_calculator method (tax-inclusive VAT extraction)."""
    
    @classmethod
    def setUpClass(cls):
        """Set up mock Device instance for testing."""
        # We need to mock the Device class since it requires certificates
        from zimra import Device
        
        # Create mock cert and key files for testing
        cls.mock_cert_path = '/tmp/mock_cert.crt'
        cls.mock_key_path = '/tmp/mock_key.key'
        
        # Mock the file operations
        with patch('builtins.open', MagicMock()):
            with patch('os.path.exists', return_value=True):
                cls.device = Device(
                    device_id='12345',
                    serialNo='TEST123',
                    activationKey='00000000',
                    cert_path=cls.mock_cert_path,
                    private_key_path=cls.mock_key_path,
                    test_mode=True
                )
    
    def test_device_15_percent_tax(self):
        """Test Device method at 15% rate."""
        result = self.device.tax_calculator(100.00, 15)
        self.assertAlmostEqual(result, 13.04, places=2)
    
    def test_device_15_5_percent_tax(self):
        """Test Device method at 15.5% rate."""
        result = self.device.tax_calculator(100.00, 15.5)
        self.assertAlmostEqual(result, 13.42, places=2)
    
    def test_device_5_percent_tax(self):
        """Test Device method at 5% rate."""
        result = self.device.tax_calculator(100.00, 5)
        self.assertAlmostEqual(result, 4.76, places=2)
    
    def test_device_zero_amount(self):
        """Test Device method with zero amount."""
        result = self.device.tax_calculator(0, 15)
        self.assertEqual(result, 0)
    
    def test_device_zero_rate(self):
        """Test Device method with zero rate."""
        result = self.device.tax_calculator(100.00, 0)
        self.assertEqual(result, 0)


class TestDeviceTaxExclusiveCalculator(unittest.TestCase):
    """Tests for the Device.tax_exclusive_calculator method (VAT on pre-tax amounts)."""
    
    @classmethod
    def setUpClass(cls):
        """Set up mock Device instance for testing."""
        from zimra import Device
        
        cls.mock_cert_path = '/tmp/mock_cert.crt'
        cls.mock_key_path = '/tmp/mock_key.key'
        
        with patch('builtins.open', MagicMock()):
            with patch('os.path.exists', return_value=True):
                cls.device = Device(
                    device_id='12345',
                    serialNo='TEST123',
                    activationKey='00000000',
                    cert_path=cls.mock_cert_path,
                    private_key_path=cls.mock_key_path,
                    test_mode=True
                )
    
    # ==================== Basic Functionality Tests ====================
    
    def test_basic_15_percent_exclusive(self):
        """Test VAT calculation at 15% rate on pre-tax amount."""
        # $100 pre-tax, 15% VAT = $100 * 0.15 = $15.00
        result = self.device.tax_exclusive_calculator(100.00, 15)
        self.assertAlmostEqual(result, 15.00, places=2)
    
    def test_basic_15_5_percent_exclusive(self):
        """Test VAT calculation at 15.5% rate on pre-tax amount."""
        # $100 pre-tax, 15.5% VAT = $100 * 0.155 = $15.50
        result = self.device.tax_exclusive_calculator(100.00, 15.5)
        self.assertAlmostEqual(result, 15.50, places=2)
    
    def test_basic_5_percent_exclusive(self):
        """Test VAT calculation at 5% rate on pre-tax amount."""
        # $100 pre-tax, 5% VAT = $100 * 0.05 = $5.00
        result = self.device.tax_exclusive_calculator(100.00, 5)
        self.assertAlmostEqual(result, 5.00, places=2)
    
    def test_basic_20_percent_exclusive(self):
        """Test VAT calculation at 20% rate on pre-tax amount."""
        # $200 pre-tax, 20% VAT = $200 * 0.20 = $40.00
        result = self.device.tax_exclusive_calculator(200.00, 20)
        self.assertAlmostEqual(result, 40.00, places=2)
    
    # ==================== Edge Cases ====================
    
    def test_exclusive_zero_amount(self):
        """Test tax exclusive calculation with zero amount."""
        result = self.device.tax_exclusive_calculator(0, 15)
        self.assertEqual(result, 0)
    
    def test_exclusive_zero_rate(self):
        """Test tax exclusive calculation with zero rate."""
        result = self.device.tax_exclusive_calculator(100.00, 0)
        self.assertEqual(result, 0)
    
    def test_exclusive_small_amount(self):
        """Test tax exclusive calculation with small amount."""
        # $0.87 at 15.5% = $0.13
        result = self.device.tax_exclusive_calculator(0.87, 15.5)
        self.assertAlmostEqual(result, 0.13, places=2)
    
    def test_exclusive_rounding_on_multiple_items(self):
        """
        Test rounding behavior - this is the issue documented in the codebase.
        Per-line: 4 items @ $0.87 = $0.52 (4 * $0.13)
        On-total: $3.48 × 15.5% = $0.54
        
        The function calculates on single items, so we expect $0.13 per item.
        """
        single_item_vat = self.device.tax_exclusive_calculator(0.87, 15.5)
        # Per-item VAT should be $0.13
        self.assertAlmostEqual(single_item_vat, 0.13, places=2)
        
        # Total VAT (should be calculated on sum, not per-item)
        total_vat = self.device.tax_exclusive_calculator(3.48, 15.5)  # 4 * 0.87
        self.assertAlmostEqual(total_vat, 0.54, places=2)
    
    # ==================== Zimbabwe-Specific Scenarios ====================
    
    def test_exclusive_zimbabwe_15_5_wholesale(self):
        """Test wholesale scenario at 15.5% (tax exclusive pricing)."""
        # Wholesale goods at $1,500 pre-tax
        result = self.device.tax_exclusive_calculator(1500.00, 15.5)
        self.assertAlmostEqual(result, 232.50, places=2)
    
    def test_exclusive_zimbabwe_5_percent(self):
        """Test 5% withholding tax on pre-tax amount."""
        # Professional services at $750 pre-tax, 5% withholding
        result = self.device.tax_exclusive_calculator(750.00, 5)
        self.assertAlmostEqual(result, 37.50, places=2)


class TestTaxCalculationConsistency(unittest.TestCase):
    """Tests to verify consistency between tax-inclusive and tax-exclusive calculations."""
    
    @classmethod
    def setUpClass(cls):
        """Set up mock Device instance for testing."""
        from zimra import Device
        
        cls.mock_cert_path = '/tmp/mock_cert.crt'
        cls.mock_key_path = '/tmp/mock_key.key'
        
        with patch('builtins.open', MagicMock()):
            with patch('os.path.exists', return_value=True):
                cls.device = Device(
                    device_id='12345',
                    serialNo='TEST123',
                    activationKey='00000000',
                    cert_path=cls.mock_cert_path,
                    private_key_path=cls.mock_key_path,
                    test_mode=True
                )
    
    def test_inclusive_exclusive_roundtrip(self):
        """Test that tax-inclusive extraction matches tax-exclusive addition."""
        # Start with pre-tax amount
        pre_tax = Decimal('100.00')
        tax_rate = Decimal('15.5')
        
        # Calculate VAT using exclusive method
        vat_exclusive = self.device.tax_exclusive_calculator(float(pre_tax), float(tax_rate))
        
        # Total with tax
        total_with_tax = float(pre_tax + Decimal(str(vat_exclusive)))
        
        # Extract VAT using inclusive method
        vat_inclusive = self.device.tax_calculator(total_with_tax, float(tax_rate))
        
        # Both VAT amounts should match (within rounding tolerance)
        self.assertAlmostEqual(vat_exclusive, vat_inclusive, places=1)
    
    def test_standalone_matches_device_method(self):
        """Test that standalone tax_calculator matches Device.tax_calculator."""
        test_cases = [
            (100.00, 15),
            (250.00, 15.5),
            (500.00, 5),
            (1000.00, 0),
        ]
        
        for amount, rate in test_cases:
            with self.subTest(amount=amount, rate=rate):
                standalone_result = tax_calculator(amount, rate)
                device_result = self.device.tax_calculator(amount, rate)
                self.assertEqual(standalone_result, device_result)


class TestTaxCalculatorReturnType(unittest.TestCase):
    """Tests to verify return types are correct."""
    
    def test_returns_float(self):
        """Verify tax_calculator returns a float."""
        result = tax_calculator(100.00, 15)
        self.assertIsInstance(result, float)
    
    def test_returns_two_decimal_places(self):
        """Verify result is rounded to 2 decimal places."""
        result = tax_calculator(123.456, 15.5)
        # Convert to string and check decimal places
        str_result = f"{result:.10f}"  # Get many decimal places
        decimal_part = str_result.split('.')[1]
        # The result should effectively be 2 decimal places
        significant_decimals = decimal_part.rstrip('0')
        self.assertLessEqual(len(significant_decimals), 2)


if __name__ == '__main__':
    unittest.main(verbosity=2)
