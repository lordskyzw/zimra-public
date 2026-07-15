# 🇿🇼 Zimra Python Client for ZIMRA FDMS

A Python library for interacting with Zimbabwe Revenue Authority's **Fiscal Device Management System (FDMS)**. Handles device registration, receipt fiscalization, cryptographic signing, tax calculations, and fiscal day management — so you don't have to.

```bash
pip install zimra
```

> [!IMPORTANT]
> **FDMS is a stateful system.** You are responsible for tracking your own `fiscalDayNo`, `receiptCounter`, and `receiptGlobalNo`. This library does not persist state between calls.

---

## Table of Contents

- [Quick Start](#quick-start)
- [Installation](#installation)
- [Core Concepts](#core-concepts)
- [Tutorial: Your First Fiscal Day](#tutorial-your-first-fiscal-day)
  - [Step 1 — Register a New Device](#step-1--register-a-new-device)
  - [Step 2 — Initialize the Device](#step-2--initialize-the-device)
  - [Step 3 — Get Device Configuration](#step-3--get-device-configuration)
  - [Step 4 — Open a Fiscal Day](#step-4--open-a-fiscal-day)
  - [Step 5 — Prepare & Submit a Receipt](#step-5--prepare--submit-a-receipt)
  - [Step 6 — Generate QR Code](#step-6--generate-qr-code)
  - [Step 7 — Close the Fiscal Day](#step-7--close-the-fiscal-day)
- [Tax-Inclusive vs Tax-Exclusive Receipts](#tax-inclusive-vs-tax-exclusive-receipts)
- [Credit Notes & Debit Notes](#credit-notes--debit-notes)
- [Receipt Data Format](#receipt-data-format)
- [Tax Rates (2026)](#tax-rates-2026)
- [API Reference](#api-reference)
- [Helper Functions](#helper-functions)
- [Running Tests](#running-tests)
- [Contributing](#contributing)
- [License](#license)

---

## Quick Start

```python
from zimra import Device, register_new_device
from datetime import datetime

# 1. Register device (only once — generates cert + private key)
register_new_device(
    fiscal_device_serial_no="9029D38C011B",
    device_id="10626",
    activation_key="00398834",
    folder_name="certs",
    prod=False  # True for production
)

# 2. Initialize
device = Device(
    device_id="10626",
    serialNo="9029D38C011B",
    activationKey="00398834",
    cert_path="certs/certificate.crt",
    private_key_path="certs/decrypted_key.key",
    test_mode=True
)

# 3. Open day → Prepare receipt → Submit → Close day
device.openDay(fiscalDayNo=1)

receipt_data = {
    "receiptType": "FISCALINVOICE",
    "receiptCurrency": "USD",
    "receiptCounter": 1,
    "receiptGlobalNo": 1,
    "invoiceNo": "INV-001",
    "receiptDate": datetime.now().strftime('%Y-%m-%dT%H:%M:%S'),
    "receiptLines": [
        {"item_name": "Widget", "tax_percent": 15.5, "quantity": 2, "unit_price": 10.00},
        {"item_name": "Tax-free item", "tax_percent": 0, "quantity": 1, "unit_price": 5.00},
    ],
    "receiptPayments": [{"moneyTypeCode": 0, "paymentAmount": 25.00}]
}

prepared = device.prepareReceipt(receipt_data)
result = device.submitReceipt(prepared)
print(result)
```

---

## Installation

### From PyPI (recommended)

```bash
pip install zimra
```

### From source

```bash
git clone https://github.com/lordskyzw/zimra-public.git
cd zimra-public
pip install -r requirements.txt
```

### Dependencies

| Package | Purpose |
|---|---|
| `requests` | HTTPS communication with FDMS API |
| `pycryptodome` | RSA signing (PKCS#1 v1.5 + SHA-256) |
| `cryptography` | Certificate/CSR generation |
| `bson` | ObjectId conversion for MongoDB users |

---

## Core Concepts

**FDMS** (Fiscal Device Management System) is ZIMRA's system for tracking taxable transactions. Here's the flow:

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  Register    │────▶│  Open Day    │────▶│  Submit      │────▶│  Close Day   │
│  Device      │     │              │     │  Receipts    │     │              │
│  (once)      │     │  (daily)     │     │  (per sale)  │     │  (daily)     │
└──────────────┘     └──────────────┘     └──────────────┘     └──────────────┘
```

**Key rules:**
- A **fiscal day** must be opened before submitting any receipts
- Each receipt gets a **global number** (monotonically increasing across all days) and a **counter** (per-day)
- Every receipt is **cryptographically signed** with your device's private key
- Fiscal days must be **closed** before opening the next one
- Receipts are **tax-inclusive** or **tax-exclusive** — use the corresponding `prepare` method

---

## Tutorial: Your First Fiscal Day

This walkthrough takes you from zero to a submitted receipt on the ZIMRA test environment.

### Step 1 — Register a New Device

Registration only needs to happen **once**. It generates an RSA keypair, creates a CSR, sends it to ZIMRA, and saves the resulting certificate and private key to disk.

```python
from zimra import register_new_device

register_new_device(
    fiscal_device_serial_no="9029D38C011B",  # Your device serial number
    device_id="10626",                        # Assigned by ZIMRA
    activation_key="00398834",                # Assigned by ZIMRA
    model_name="Server",                      # Your POS model name
    folder_name="certs",                      # Directory to save cert + key
    certificate_filename="certificate",       # Output: certs/certificate.crt
    private_key_filename="decrypted_key",     # Output: certs/decrypted_key.key
    prod=False                                # False = test, True = production
)
```

**Output files:**
```
certs/
├── certificate.crt     # Client certificate (from ZIMRA)
└── decrypted_key.key   # RSA 2048-bit private key
```

> [!WARNING]
> Keep your private key secure. Anyone with access to it can sign receipts as your device.

---

### Step 2 — Initialize the Device

```python
from zimra import Device

device = Device(
    device_id="10626",
    serialNo="9029D38C011B",
    activationKey="00398834",
    cert_path="certs/certificate.crt",
    private_key_path="certs/decrypted_key.key",
    test_mode=True,                      # False for production
    deviceModelName="Server",            # Must match what you registered with
    deviceModelVersion="v1",
    company_name="MyCompany"
)
```

> [!CAUTION]
> The `deviceModelName` and `deviceModelVersion` **must match exactly** what you used during registration. A mismatch will result in `403 Forbidden` errors on every API call.

---

### Step 3 — Get Device Configuration

Always call `getConfig()` after initialization to retrieve your taxpayer details and applicable tax rates:

```python
config = device.getConfig()
print(config)
```

**Example response:**
```python
{
    'taxPayerName': 'MY COMPANY (PVT) LTD',
    'taxPayerTIN': '2000253679',
    'vatNumber': '220227652',
    'deviceSerialNo': '9029D38C011B',
    'deviceBranchName': 'MY COMPANY (PVT) LTD',
    'deviceBranchAddress': {
        'province': 'Harare', 'street': 'Main St', 'houseNo': '1', 'city': 'Harare'
    },
    'applicableTaxes': [
        {'taxName': 'Exempt', 'taxID': 1},
        {'taxPercent': 0.0, 'taxName': 'Zero rate 0%', 'taxID': 2},
        {'taxPercent': 15.5, 'taxName': 'Standard rated 15.5%', 'taxID': 515},
        {'taxPercent': 5.0, 'taxName': 'Non-VAT Withholding Tax', 'taxID': 514}
    ],
    'certificateValidTill': '2027-07-31T06:26:09',
    'qrUrl': 'https://fdmstest.zimra.co.zw'
}
```

---

### Step 4 — Open a Fiscal Day

```python
result = device.openDay(fiscalDayNo=1)
print(result)
# {'fiscalDayNo': 1, 'operationID': '0HN4FDK6T1CNI:00000001'}
```

The method will:
- ✅ Verify the previous day is closed before opening a new one
- ✅ Verify the day number is greater than the last closed day
- ❌ Return an error dict if either check fails

```python
# Error case — day already open:
# {'error': 'Fiscal Day 1 is not closed'}
```

---

### Step 5 — Prepare & Submit a Receipt

This is a **two-step process**: prepare (local) → submit (API call).

#### 5a. Build the receipt data

```python
from datetime import datetime

receipt_data = {
    "receiptType": "FISCALINVOICE",       # "FISCALINVOICE" | "CREDITNOTE" | "DEBITNOTE"
    "receiptCurrency": "USD",              # "USD" | "ZWG"
    "receiptCounter": 1,                   # Per-day counter (you track this)
    "receiptGlobalNo": 1,                  # Global counter (you track this)
    "invoiceNo": "INV-001",                # Your unique invoice identifier
    "receiptDate": datetime.now().strftime('%Y-%m-%dT%H:%M:%S'),
    "receiptLines": [
        {
            "item_name": "Laptop",
            "tax_percent": 15.5,           # 15.5% VAT (standard 2026 rate)
            "quantity": 1,
            "unit_price": 899.99,
            "hs_code": "84713010"          # Optional — defaults to '04021099'
        },
        {
            "item_name": "Mouse",
            "tax_percent": 15.5,
            "quantity": 2,
            "unit_price": 15.00
        },
        {
            "item_name": "USB Cable",
            "tax_percent": 0,              # Zero-rated
            "quantity": 3,
            "unit_price": 5.00
        },
        {
            "item_name": "Donation item",
            "tax_percent": "exempt",       # Exempt — use string "E" or "exempt"
            "quantity": 1,
            "unit_price": 10.00
        }
    ],
    "receiptPayments": [
        {
            "moneyTypeCode": 0,            # 0 = CASH, 1 = CARD
            "paymentAmount": 959.99        # Total paid by customer
        }
    ]
}
```

#### 5b. Prepare the receipt

`prepareReceipt` does all the heavy lifting:
- Validates all mandatory fields are present
- Calculates `receiptTotal` from line items
- Maps `tax_percent` values to ZIMRA tax IDs
- Generates consolidated `receiptTaxes` entries
- Computes the SHA-256 hash and RSA signature

```python
prepared = device.prepareReceipt(
    receiptData=receipt_data,
    receiptPrintForm="Receipt48"       # Optional, defaults to "Receipt48"
)
```

You can also chain receipts by passing the hash from the previous receipt:
```python
prepared = device.prepareReceipt(
    receiptData=receipt_data,
    previousReceiptHash="abc123..."    # Hash from previous receipt's signature
)
```

#### 5c. Submit the receipt

```python
result = device.submitReceipt(prepared)
print(result)
```

**Success response:**
```python
{
    'receiptID': 12345,
    'receiptGlobalNo': 1,
    'serverSignature': { ... },
    'operationID': '...'
}
```

**Error response:**
```python
{400: '{"errors": [...]}'}
```

---

### Step 6 — Generate QR Code

After a successful submission, generate the verification QR code URL:

```python
qr_string = device.generate_qr_code(
    signature=result['serverSignature']['signature'],  # From submit response
    receipt_global_no=1,
    receipt_date=datetime.now().date()
)
print(qr_string)
# https://fdmstest.zimra.co.zw/00000106262202202600000000011a2b3c4d5e6f7890
```

Print this QR code on the physical receipt — customers can scan it to verify the receipt with ZIMRA.

---

### Step 7 — Close the Fiscal Day

At the end of the business day, close the fiscal day with your day's counters:

```python
fiscal_day_counters = [
    {
        "fiscalCounterType": "SaleByTax",
        "fiscalCounterCurrency": "USD",
        "fiscalCounterTaxPercent": 15.5,
        "fiscalCounterTaxID": 515,
        "fiscalCounterValue": 929.99
    },
    {
        "fiscalCounterType": "SaleByTax",
        "fiscalCounterCurrency": "USD",
        "fiscalCounterTaxPercent": 0.0,
        "fiscalCounterTaxID": 2,
        "fiscalCounterValue": 15.00
    },
    {
        "fiscalCounterType": "SaleTaxByTax",
        "fiscalCounterCurrency": "USD",
        "fiscalCounterTaxPercent": 15.5,
        "fiscalCounterTaxID": 515,
        "fiscalCounterValue": 124.89
    },
    {
        "fiscalCounterType": "BalanceByMoneyType",
        "fiscalCounterCurrency": "USD",
        "fiscalCounterMoneyType": 0,
        "fiscalCounterValue": 959.99
    }
]

result = device.closeDay(
    fiscalDayNo=1,
    fiscalDayDate="2026-02-22",
    lastReceiptCounterValue=1,          # Last receiptCounter used today
    fiscalDayCounters=fiscal_day_counters
)
print(result)
```

For an **empty day** (no receipts), pass empty counters:

```python
result = device.closeDay(
    fiscalDayNo=1,
    fiscalDayDate="2026-02-22",
    lastReceiptCounterValue=None,
    fiscalDayCounters=[]
)
```

---

## Tax-Inclusive vs Tax-Exclusive Receipts

The library provides **two** receipt preparation methods depending on how your prices are structured:

| Method | Prices include VAT? | `receiptLinesTaxInclusive` |
|---|---|---|
| `prepareReceipt()` | ✅ Yes — prices already contain VAT | `True` |
| `prepareReceiptTaxExclusive()` | ❌ No — prices are pre-tax | `False` |

### Tax-Inclusive Example (most retail scenarios)

Prices on the shelf are what the customer pays:

```python
# Price is $115.50 (includes $15.50 VAT at 15.5%)
receipt_data = {
    "receiptType": "FISCALINVOICE",
    "receiptCurrency": "USD",
    "receiptCounter": 1,
    "receiptGlobalNo": 1,
    "invoiceNo": "INV-100",
    "receiptDate": datetime.now().strftime('%Y-%m-%dT%H:%M:%S'),
    "receiptLines": [
        {"item_name": "Product A", "tax_percent": 15.5, "quantity": 1, "unit_price": 115.50}
    ],
    "receiptPayments": [{"moneyTypeCode": 0, "paymentAmount": 115.50}]
}

prepared = device.prepareReceipt(receipt_data)
```

### Tax-Exclusive Example (wholesale / B2B)

Prices are quoted before tax, VAT is added on top:

```python
# Price is $100.00 + $15.50 VAT = $115.50 total
receipt_data = {
    "receiptType": "FISCALINVOICE",
    "receiptCurrency": "USD",
    "receiptCounter": 1,
    "receiptGlobalNo": 1,
    "invoiceNo": "INV-200",
    "receiptDate": datetime.now().strftime('%Y-%m-%dT%H:%M:%S'),
    "receiptLines": [
        {"item_name": "Product A", "tax_percent": 15.5, "quantity": 1, "unit_price": 100.00}
    ],
    "receiptPayments": [{"moneyTypeCode": 0, "paymentAmount": 115.50}]
}

prepared = device.prepareReceiptTaxExclusive(receipt_data)
```

> [!NOTE]
> `prepareReceiptTaxExclusive` automatically calculates the VAT on the **summed total** (not per-line) to avoid rounding errors. For example, 4 items @ $0.87 at 15.5% → tax is calculated on $3.48, not 4 × tax($0.87).

---

## Credit Notes & Debit Notes

For refunds or adjustments, use `receiptType` of `"CREDITNOTE"` or `"DEBITNOTE"`. These require two additional fields:

```python
credit_note = {
    "receiptType": "CREDITNOTE",
    "receiptCurrency": "USD",
    "receiptCounter": 2,
    "receiptGlobalNo": 2,
    "invoiceNo": "CN-001",
    "receiptDate": datetime.now().strftime('%Y-%m-%dT%H:%M:%S'),
    "receiptLines": [
        {"item_name": "Returned Widget", "tax_percent": 15.5, "quantity": 1, "unit_price": 10.00}
    ],
    "receiptPayments": [{"moneyTypeCode": 0, "paymentAmount": 10.00}],

    # Required for credit/debit notes:
    "receiptNotes": "Customer returned defective item",
    "creditDebitNote": {
        "receiptID": 12345,              # Original receipt ID from ZIMRA
        "receiptGlobalNo": 1,            # Original receipt's global number
        "fiscalDayNo": 1,                # Day the original receipt was issued
        "receiptDate": "2026-02-22T10:00:00"
    }
}

prepared = device.prepareReceipt(credit_note)
result = device.submitReceipt(prepared)
```

---

## Receipt Data Format

### Mandatory Fields

| Field | Type | Description |
|---|---|---|
| `receiptType` | `str` | `"FISCALINVOICE"`, `"CREDITNOTE"`, or `"DEBITNOTE"` |
| `receiptCurrency` | `str` | `"USD"` or `"ZWG"` |
| `receiptCounter` | `int` | Per-day receipt counter (you manage this) |
| `receiptGlobalNo` | `int` | Global receipt counter across all days (you manage this) |
| `invoiceNo` | `str` | Your unique invoice identifier |
| `receiptDate` | `str` or `datetime` | Timestamp — format: `YYYY-MM-DDTHH:MM:SS` |
| `receiptLines` | `list` | Line items (see below) |
| `receiptPayments` | `list` | Payment entries (see below) |

### Receipt Line Format

| Field | Type | Required | Description |
|---|---|---|---|
| `item_name` | `str` | ✅ | Product name |
| `tax_percent` | `float` or `str` | ✅ | Tax rate: `15.5`, `5`, `0`, or `"exempt"` / `"E"` |
| `quantity` | `int`/`float` | ✅ | Quantity sold |
| `unit_price` | `float` | ✅ | Price per unit |
| `hs_code` | `str` | ❌ | HS tariff code (defaults to `'04021099'`) |

### Payment Entry Format

| Field | Type | Description |
|---|---|---|
| `moneyTypeCode` | `int` | `0` = Cash, `1` = Card |
| `paymentAmount` | `float` | Amount paid |

### Optional Fields

| Field | Type | When Required |
|---|---|---|
| `buyerData` | `dict` | Optional — buyer information |
| `creditDebitNote` | `dict` | **Required** for credit/debit notes |
| `receiptNotes` | `str` | **Required** for credit/debit notes |

---

## Tax Rates (2026)

As of 2026, ZIMRA applies the following tax structure:

| Tax Type | Rate | Tax ID (test) | `tax_percent` value |
|---|---|---|---|
| Standard VAT | **15.5%** | 515 | `15.5` |
| Withholding Tax | 5% | 514 | `5` |
| Zero-rated | 0% | 2 | `0` |
| Exempt | — | 3 | `"exempt"` or `"E"` |

> [!NOTE]
> The standard VAT rate changed from 15% to **15.5%** in 2026. The library handles both rates for backwards compatibility — if `15` is passed but not available in your device's applicable taxes, it falls back to `15.5`.

---

## API Reference

### Top-Level Functions

#### `register_new_device(...)`

Registers a new fiscal device with ZIMRA. Generates an RSA keypair, submits a CSR, and saves the certificate and private key.

```python
register_new_device(
    fiscal_device_serial_no: str,
    device_id: str,
    activation_key: str,
    model_name: str = 'Server',
    folder_name: str = 'prod',
    certificate_filename: str = 'certificate',
    private_key_filename: str = 'decrypted_key',
    prod: bool = False
)
```

---

### `Device` Class

#### `Device.__init__(...)`

```python
Device(
    device_id: str,            # ZIMRA-assigned device ID
    serialNo: str,             # Device serial number
    activationKey: str,        # Activation key from ZIMRA
    cert_path: str,            # Path to client certificate (.crt)
    private_key_path: str,     # Path to private key (.key)
    test_mode: bool = True,    # True = test API, False = production
    deviceModelName: str = 'Server',
    deviceModelVersion: str = 'v1',
    company_name: str = "NexusClient"
)
```

#### `device.getConfig() → dict`

Retrieves taxpayer details, branch info, applicable taxes, and certificate validity.

#### `device.getStatus() → dict`

Returns current fiscal day number and status (`FiscalDayClosed` / `FiscalDayOpened`).

#### `device.ping() → dict`

Health check — verifies the device can communicate with FDMS.

#### `device.openDay(fiscalDayNo: int) → dict`

Opens a new fiscal day. Validates state and day number before sending.

#### `device.prepareReceipt(receiptData, applicableTaxes=None, previousReceiptHash=None, receiptPrintForm="Receipt48") → dict`

Prepares a **tax-inclusive** receipt: validates fields, calculates taxes, computes totals, and signs the receipt.

#### `device.prepareReceiptTaxExclusive(receiptData, applicableTaxes=None, previousReceiptHash=None, receiptPrintForm="Receipt48") → dict`

Prepares a **tax-exclusive** receipt: same as above, but line prices are pre-tax and VAT is added on top.

#### `device.submitReceipt(receiptData: dict) → dict`

Submits a prepared receipt to FDMS. Returns the server response including receipt ID and server signature.

#### `device.generate_qr_code(signature, receipt_global_no, receipt_date) → str`

Generates the QR code verification URL string from a receipt's signature.

#### `device.closeDay(fiscalDayNo, fiscalDayDate, lastReceiptCounterValue, fiscalDayCounters) → dict`

Closes the fiscal day. Signs the day's counters and submits to FDMS.

#### `device.renewCertificate()`

Renews the device certificate using the existing private key.

---

## Helper Functions

These standalone functions help preprocess receipt data before passing it to the `Device` methods:

#### `preprocess_receipt(receipt_data: dict) → dict`

Sanitizes receipt data for **tax-inclusive** receipts. Converts `unit_price` and `quantity` to strings, calculates `line_total` using `Decimal` for precision, and sets `paymentAmount`.

```python
from zimra import preprocess_receipt

raw_data = {
    "receiptLines": [
        {"item_name": "A", "tax_percent": 15.5, "quantity": 2, "unit_price": 10.0}
    ],
    "receiptPayments": [{"moneyTypeCode": 0, "paymentAmount": 0}],
    # ... other fields
}

clean_data = preprocess_receipt(raw_data)
# clean_data["receiptPayments"][0]["paymentAmount"] is now 20.00
```

#### `preprocess_tax_exclusivereceipt(receipt_data: dict) → dict`

Same as above but for **tax-exclusive** receipts. Does **not** auto-set `paymentAmount` (since the total changes after tax is added).

#### `tax_calculator(sale_amount, tax_rate) → float`

Extracts VAT from a tax-inclusive amount:

```python
from zimra import tax_calculator

vat = tax_calculator(115.50, 15.5)   # → 15.50
vat = tax_calculator(100.00, 0)      # → 0.0
```

---

## Running Tests

```bash
# Full test suite
python -m unittest discover -s zimra/tests -v

# Tax calculation tests only
python -m unittest zimra.tests.test_tax_calculations -v

# Fiscalization tests
python -m unittest zimra.test_fiscalization -v
```

---

## Contributing

Contributions are welcome! This project is actively developed and there are many areas for improvement.

### Getting Started

1. **Fork and clone**
   ```bash
   git clone https://github.com/lordskyzw/zimra-public.git
   cd zimra-public
   ```

2. **Set up your environment**
   ```bash
   python3 -m venv zimraenv
   source zimraenv/bin/activate  # Windows: zimraenv\Scripts\activate
   pip install -r requirements.txt
   ```

3. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

### Code Style

- Follow [PEP 8](https://pep8.org/)
- Add docstrings to all public functions
- Use type hints
- Use `Decimal` for all monetary calculations (never raw `float` arithmetic)

### Pull Request Checklist

- [ ] All tests pass (`python -m unittest discover -s zimra/tests -v`)
- [ ] New features include tests
- [ ] README updated if behavior changes
- [ ] One feature or fix per PR

### Areas for Contribution

- [ ] Additional unit tests for edge cases
- [✅] Support for additional receipt types (we officially support all fiscal documents in all their receipt types: FISCALINVOICE, CREDITNOTE, DEBITNOTE, Receipt48, ReceiptA4)
- [ ] Improved error handling and validation
- [ ] Async API support
- [ ] Batch receipt submission
- [ ] CLI tool for common operations

### Reporting Issues

Please include: a clear description, steps to reproduce, expected vs actual behavior, Python version, OS, and any relevant logs.

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
