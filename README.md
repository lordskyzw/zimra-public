this is my in house library for interacting with Zimra's FDMS system 
# Fiscal Device Management System (FDMS) API Client

This repository provides a Python client for interacting with the Fiscal Device Gateway API (aka FDMS) provided by ZIMRA. The client can be used to manage various operations related to fiscal devices, such as registering a device, fetching configurations, issuing certificates, and handling fiscal day operations.

PLEASE NOTE THAT THE FDMS IS A STATEFUL SYSTEM, SO YOU NEED TO KEEP TRACK OF THE FISCAL DAY NUMBER AND THE RECEIPT COUNTERS. THE CLIENT DOES NOT KEEP TRACK OF THESE FOR YOU



## Table of Contents

- [Installation](#installation)
- [Usage](#usage)
- [Class Methods](#class-methods)
- [Contributing](#contributing)
- [License](#license)

## Installation

To use this client, clone the repository and install the necessary dependencies:

```bash
git clone https://github.com/lordskyzw/zimra-public.git
cd zimra-public
pip install -r requirements.txt
```

Or you can just pip install from pypi

```bash
pip install zimra
```

## Usage

You can use the `Device` class to interact with the Fiscal Device Gateway API. Below is an example of how to initialize the class and perform some operations.

### Example

```python
from zimra import Device

# Initialize the device in test mode
device = Device(
    device_id: str, 
    serialNo: str, 
    activationKey: str, 
    cert_path: str, 
    private_key_path:str, 
    test_mode:bool =True, 
    deviceModelName: str='Model123', 
    deviceModelVersion:str = '1.0',
    company_name:str ="Nexus"
)

# Open a fiscal day
fiscal_day_status = device.openDay(fiscalDayNo=102)
print(fiscal_day_status)
```


```python
# Submit a receipt
example_invoice = {
  "deviceID": 12345,
  "receiptType": "FISCALINVOICE",
  "receiptCurrency": "USD",
  "receiptCounter": 1,
  "receiptGlobalNo": 1,
  "invoiceNo": "mz-1",
  "receiptDate": datetime.now().strftime('%Y-%m-%dT%H:%M:%S'), #example: "2021-09-30T12:00:00",
  "receiptLines": [
    {"item_name": "0percent_item",
      "tax_percent": 0.00,
      "quantity": 1,
      "unit_price": 10.00
    },
    {"item_name": "15percent_item2",
      "tax_percent": 15.5,
      "quantity": 1,
      "unit_price": 20.00
    }
  ],
  "receiptPayments":[{
    "moneyTypeCode": 0,
    "paymentAmount": 30.00
    }]
}

receipt = device.prepareReceipt(example_invoice) # this method does all the heavy lifting for you

receipt_status = device.submitReceipt(receipt) # this method submits the receipt to the fiscal device management system and if the receipt has no errors, a QR url is returned which can be used to make the qr code to be printed on receipt, otherwise it returns the error message
print(receipt_status)
```

## Class Methods

### `__init__(self, test_mode=False, *args)`

Initializes the Device class. 

- `test_mode`: Boolean to specify whether to use the test environment or production environment.

### `register(self)`

Registers the device.

### `getConfig(self)`

Fetches the device configuration and updates the device attributes.

### `issueCertificate(self)`

Issues a certificate for the device.

### `getStatus(self)`

Gets the current status of the device.

### `openDay(self, fiscalDayNo, fiscalDayOpened=None)`

Opens a fiscal day.

### `prepareReceipt(self, receiptData)`

Prepares a receipt to be submitted to the fiscal device management system.
It calculates the taxes and formats them in the required format
It signs the receipt as well using the private key provided

### `submitReceipt(self, receiptData)`

Submits a receipt to the fiscal device gateway.

### `closeDay(self)`

Closes the fiscal day. 
It also creates the fiscal day signature based on all the day's transactions

## Contributing

Contributions are welcome! This project is still in development and there are many features that can be added to make work simpler for front end developers.

### Getting Started

1. **Fork the repository**
   ```bash
   git clone https://github.com/lordskyzw/zimra-public.git
   cd zimra-public
   ```

2. **Set up your development environment**
   ```bash
   python3 -m venv zimraenv
   source zimraenv/bin/activate  # On Windows: zimraenv\Scripts\activate
   pip install -r requirements.txt
   ```

3. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

### Running Tests

**All contributions must pass the test suite before being merged.**

Run the full test suite:
```bash
source zimraenv/bin/activate
python -m unittest discover -s zimra/tests -v
```

Run specific test modules:
```bash
# Tax calculation tests
python -m unittest zimra.tests.test_tax_calculations -v

# Fiscalization tests
python -m unittest zimra.test_fiscalization -v
```

### Code Style Guidelines

- Follow [PEP 8](https://pep8.org/) style guidelines
- Use meaningful variable and function names
- Add docstrings to all public functions and classes
- Use type hints where appropriate
- Keep functions focused and modular

### Pull Request Process

1. **Ensure all tests pass** - PRs with failing tests will not be merged
2. **Add tests for new features** - New functionality should include corresponding unit tests
3. **Update documentation** - Update the README if you're adding new features or changing existing behavior
4. **Write clear commit messages** - Describe what changed and why
5. **Keep PRs focused** - One feature or fix per PR makes review easier

### What to Contribute

Here are some areas where contributions would be especially valuable:

- [ ] Additional unit tests for edge cases
- [ ] Support for additional receipt types
- [ ] Improved error handling and validation
- [ ] Documentation improvements
- [ ] Performance optimizations
- [ ] Support for batch operations

### Reporting Issues

When reporting issues, please include:
- A clear description of the problem
- Steps to reproduce the issue
- Expected vs actual behavior
- Python version and OS information
- Relevant error messages or logs

## License

This project is licensed under the MIT License. See the LICENSE file for details.
