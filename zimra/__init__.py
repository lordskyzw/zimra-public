import os
from bson import ObjectId
import requests
import datetime
import logging
from datetime import datetime
import json
import hashlib
import base64
from collections import OrderedDict, defaultdict
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from Crypto.Signature import pkcs1_15
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from cryptography.hazmat.primitives.asymmetric import rsa

logging.basicConfig(level=logging.INFO)

'''
DISCLAIMER: THE FOLLOWING SOFTWARE IS DAUNTING AND VERY COMPLICATED. THIS FOLLOWS THE LAW THAT COMPLEXITY ALWAYS INCREASES, EVEN IN OUR ATTEMPTS TO DECREASE IT, 

PLEASE NOTE THAT THE FDMS IS A STATEFUL SYSTEM, SO YOU NEED TO KEEP TRACK OF THE FISCAL DAY NUMBER AND THE RECEIPT COUNTERS. THE LIBRARY DOES NOT KEEP TRACK OF THESE FOR YOU

IN YOUR QUEST TO UNDERSTAND WHATS GOING ON HERE WITHOUT A BACKGROUND IN FISCALISATION, I, TARMICA CHIWARA, WOULD LIKE TO WISH YOU GOOD LUCK.


Fiscal Device Gateway API can be accessed using HTTPS protocol via mTLS. 
All Fiscal Device Gateway API methods except registerDevice and getServerCertificate use CLIENT AUTHENTICATION CERTIFICATE
which is issued by FDMS.
'''

'''
This library provides an interface to interact with the ZIMRA Fiscal Device Management System (FDMS) API.
it has been updated to suit requirements for fiscal devices as per the ZIMRA FDMS API documentation. v7.2
by Panashe Arthur Mhonde (https://github.com/PhaseOfficial)
'''
__all__ = [
    'register_new_device',
    'tax_calculator',
    'Device',
    'ZimraServerError'
]

class ZimraServerError(Exception):
    """Raised when the Zimra server returns an error."""
    
    def __init__(self, status_code, message):
        self.status_code = status_code  # Store the status code for further use
        super().__init__(f"ZimraServerError {status_code}: {message}")
     

def convert_objectid_to_str(data):
    if isinstance(data, dict):
        return {k: str(v) if isinstance(v, ObjectId) else v for k, v in data.items()}
    return data


def register_new_device(
    
    fiscal_device_serial_no:str, 
    device_id:str,
    activation_key:str, 
    device_version:str = 'v1',
    model_name:str = 'Server',
    folder_name:str = 'prod', 
    certificate_filename:str='certificate', 
    private_key_filename:str='decrypted_key',
    prod:bool = False
    ):
    '''
    Parameters:

    folder_name: string (name of the prospective folder to save the certificate and file)

    fiscal_device_serial_no: string 

    device_id: string (should be 0 padded 10 digit string but confirm with Zimra first after the debacle with Kolfhurst)

    activation_key: str (should be 0 padded 8 digit string. For example: '00398834')

    certificate_filename: string (prospective file name for the certificate)

    private_key_filename: (prospective file name for the private key)

    prod: bool  (True for production, False for testing)
    '''
    if not os.path.exists(f'{folder_name}'):
        os.makedirs(f'{folder_name}')

    # Format Device serial number and device ID
    formatted_device_id = device_id.zfill(10)


    # Generate RSA private key (2048 bits)
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Save the private key to a PEM file
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    with open(f"{folder_name}/{private_key_filename}.key", "wb") as key_file:
        key_file.write(private_key_pem)
        logging.info(f"Private key saved to {folder_name}/{private_key_filename}.key")

    # Define the Common Name (CN) based on the format
    common_name = f'ZIMRA-{fiscal_device_serial_no}-{formatted_device_id}'

    # Generate CSR with the required Subject fields
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])).sign(private_key, hashes.SHA256(), default_backend())

    # Serialize CSR to PEM format
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    if prod:
        url = f'https://fdmsapi.zimra.co.zw/Public/{device_version}/{device_id}/RegisterDevice'
    else:
        url = f'https://fdmsapitest.zimra.co.zw/Public/{device_version}/{device_id}/RegisterDevice'

    headers = {
        'accept': 'application/json',
        'Content-Type': 'application/json',
        'DeviceModelName': model_name,
        'DeviceModelVersion': '1.0'
    }

    payload = {
        'activationKey': activation_key,
        'certificateRequest': csr_pem,
    }

    response = requests.post(url, json=payload, headers=headers)

    if response.status_code == 200:
        logging.info("Request was successful!")
        response_json = response.json()
        certificate_pem = response_json['certificate']

        # Save the certificate to a PEM file
        with open(f"{folder_name}/{certificate_filename}.crt", "w") as cert_file:
            cert_file.write(certificate_pem)
            logging.info(f"Certificate saved to {folder_name}/{certificate_filename}.crt")
        
    else:
        logging.fatal(f"Request failed with status code {response.status_code}")
        logging.critical(response.text)


def tax_calculator(sale_amount, tax_rate):
    # convert the tax rate to a decimal
    tax_rate = (tax_rate / 100)
    # taxAmount must be equal to (((SUM(receiptLineTotal)) * taxPercent) / (1+taxPercent)) rounded to 2 decimal places
    tax_amount = round(((sale_amount * tax_rate) / (1 + tax_rate)), 2)
    return tax_amount

class Device:
    def __init__(
            self,
            device_id: str, 
            device_version: str='v1',
            serialNo: str, 
            activationKey: str, 
            cert_path: str, 
            private_key_path:str, 
            test_mode:bool =True, 
            deviceModelName: str='Model123', 
            deviceModelVersion:str = '1.0',
            company_name:str ="NexusClient"
        ):
        self.companyName: str = company_name
        self.deviceID: int = device_id
        self.deviceModelName =deviceModelName
        self.deviceModelVersion = deviceModelVersion
        self.certPath: str = cert_path
        self.keyPath: str = private_key_path
        
        if test_mode:
            self.base_url: str = f'https://fdmsapitest.zimra.co.zw/Device/{device_version}/'
            self.qrUrl:str = 'https://fdmstest.zimra.co.zw/'
        else:
            self.base_url: str = f'https://fdmsapi.zimra.co.zw/Device/{device_version}/'
            self.qrUrl:str = 'https://fdms.zimra.co.zw/'

        self.deviceBaseUrl = f'{self.base_url}{self.deviceID}'
        
        self.serialNo = serialNo
        self.activationKey = activationKey

        # New: deviceOperatingMode will be refreshed before operations (Option A)
        self.deviceOperatingMode = None  # "Online" or "Offline"

    # ----------------------
    # Helper methods
    # ----------------------
    def refresh_operating_mode(self):
        """Refresh deviceOperatingMode by calling GetConfig"""
        try:
            config = self.getConfig()
            # getConfig returns string error or dict; guard against that
            if isinstance(config, dict) and 'deviceOperatingMode' in config:
                self.deviceOperatingMode = config['deviceOperatingMode']
                logging.info(f"Device operating mode refreshed: {self.deviceOperatingMode}")
                return self.deviceOperatingMode
            else:
                logging.warning("Could not refresh deviceOperatingMode; getConfig returned unexpected response.")
                return None
        except Exception as e:
            logging.warning(f"refresh_operating_mode failed: {e}")
            return None

    def isOffline(self):
        """Return True if deviceOperatingMode is Offline. Refreshes the mode first (Option A)."""
        self.refresh_operating_mode()
        return str(self.deviceOperatingMode).lower() == 'offline'

    def isOnline(self):
        """Return True if deviceOperatingMode is Online. Refreshes the mode first (Option A)."""
        self.refresh_operating_mode()
        return str(self.deviceOperatingMode).lower() == 'online'

    def tax_calculator(self, sale_amount:float, tax_rate: int)-> float:
        # convert the tax rate to a decimal
        tax_rate = (tax_rate / 100)
        # taxAmount must be equal to (((SUM(receiptLineTotal)) * taxPercent) / (1+taxPercent)) rounded to 2 decimal places
        tax_amount = round(((sale_amount * tax_rate) / (1 + tax_rate)), 2)
        return tax_amount
    
    def concatenate_receipt_taxes(self, receiptTaxes):
        # Sort by taxID and taxCode (empty taxCode comes first)
        receiptTaxes_sorted = sorted(receiptTaxes, key=lambda x: (x['taxID']))
        # Concatenate each line without separators
        concatenated_string = ''.join(
            f"{float(tax['taxPercent']):.2f}{int(tax['taxAmount']*100)}{int(tax['salesAmountWithTax']*100)}" 
            for tax in receiptTaxes_sorted
        )

        return concatenated_string


    def get_hash(self, data:str)->str:
        """Compute SHA256 hash and encode it in Base64."""
        hash_object = hashlib.sha256(data.encode('utf-8'))
        return base64.b64encode(hash_object.digest()).decode('utf-8')
    
    def sign_data(self, data:str)->str:
        with open(self.keyPath, 'rb') as key_file:
            private_key_pem = key_file.read()
        key = RSA.import_key(private_key_pem)
        h = SHA256.new(data.encode('utf-8'))
        signature = pkcs1_15.new(key).sign(h)
        return base64.b64encode(signature).decode('utf-8')
    
    def getConfig(self)->dict:
        '''returns:
        {
            'taxPayerName': 'SAINTFORD VENTURES', 
            'taxPayerTIN': '2000253679', 
            'vatNumber': '220227652', 
            'deviceSerialNo': '9029D38C011B', 
            'deviceBranchName': 'SAINTFORD VENTURES (PVT) LTD', 
            'deviceBranchAddress': {'province': 'Harare', 'street': 'Plymouth road', 'houseNo': '44', 'city': 'Harare'}, 
            'deviceBranchContacts': {'phoneNo': '0776298764', 'email': 'saintfordventures@gmail.com'}, 
            'deviceOperatingMode': 'Online', 
            'taxPayerDayMaxHrs': 24, 
            'applicableTaxes': [{
                'taxName': 'Exempt', 
                'validFrom': '2023-01-01T00:00:00', 
                'taxID': 1
                }, 
                {'taxPercent': 0.0, 
                'taxName': 'Zero rate 0%', 
                'validFrom': '2023-01-01T00:00:00', 
                'taxID': 2
                }, 
                {'taxPercent': 15.0, 
                'taxName': 'Standard rated 15%', 
                'validFrom': '2023-01-01T00:00:00', 
                'taxID': 3}, 
                {'taxPercent': 5.0, 
                'taxName': 'Non-VAT Withholding Tax', 
                'validFrom': '2024-01-01T00:00:00', 
                'taxID': 514
                }], 
            'certificateValidTill': '2027-07-31T06:26:09', 
            'qrUrl': 'https://fdmstest.zimra.co.zw', 
            'taxpayerDayEndNotificationHrs': 2, 
            'operationID': '0HN4FDK6SREE1:00000001'
        }
        ''' 
    
        url = f'{self.deviceBaseUrl}/GetConfig'
        response = requests.get(
            url,
            cert=(self.certPath, self.keyPath),
            headers = {
                'DeviceModelName': self.deviceModelName, #this matter a whole lot more than you think, change it and you will get a 403
                'DeviceModelVersion': self.deviceModelVersion
            }
        )
        
        if response.status_code == 200:
            data = response.json()
            return data
        else:
            return({"Error": f"Error: {response.status_code} - {response.text}"})

    def renewCertificate(self):
        '''
        this function only works if there is an existing private key already
        writes the certificate to companyname.crt & companyname.pem
        '''

        device_id = self.deviceID
        serial_no = self.serialNo
        device_id_padded = str(device_id).zfill(10)
        cn_value = f"ZIMRA-{serial_no}-{device_id_padded}"

        with open(self.keyPath, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )

        hash_algorithm = hashes.SHA256()

        # Build the CSR
        csr_builder = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, cn_value),

        ]))

        # Sign the CSR
        csr = csr_builder.sign(private_key, hash_algorithm, default_backend())

        # Serialize CSR to PEM format
        csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode('utf-8')

        # Prepare the request data with additional fields
        url = f'{self.deviceBaseUrl}/IssueCertificate'
        headers = {
            'DeviceModelName': self.deviceModelName,
            'DeviceModelVersion': self.deviceModelVersion,
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        data = {
            "certificateRequest": csr_pem,
        }


        try:
            response = requests.post(
                url,
                headers=headers, 
                cert=(self.certPath, self.keyPath),
                json=data,
            )
            response.raise_for_status() 
            response_json = response.json()
            certificate = response_json.get('certificate')
            if certificate:
                # Save the certificate to a file
                with open(f'{self.companyName}.crt', 'w') as cert_file:
                    cert_file.write(certificate)
                return certificate
            else:
                return {"Error": "No certificate returned from IssueCertificate"}
        except requests.exceptions.HTTPError as http_err:
            # Print detailed error message from the response
            try:
                error_response = response.json()
            except Exception:
                error_response = response.text
            ret_statement = f"HTTP error occurred: {http_err}\n\nResponse: {error_response}"
            return {"Error": ret_statement}
        except Exception as err:
            return({"Error": f"Other error occurred: {err}"})

    def getStatus(self)->dict:
        '''
        returns:
        {
            'fiscalDayNo': 1,
            'fiscalDayStatus': 'FiscalDayClosed',
        }

        '''
        url = f'{self.deviceBaseUrl}/GetStatus'
        response = requests.get(
            url,
            cert=(self.certPath, self.keyPath),
            headers = {
                'DeviceModelName': self.deviceModelName, #this matter a whole lot more than you think, change it and you will get a 403
                'DeviceModelVersion': self.deviceModelVersion
            }
        )

        if response.status_code == 200:
            data = response.json()
            return data
        else:
            data = {"Error": f"Error: {response.status_code} - {response.text}"}
            return data

    def ping(self)->dict:
        url = f'{self.deviceBaseUrl}/Ping'
        headers = {
            'DeviceModelName': self.deviceModelName,
            'DeviceModelVersion': self.deviceModelVersion,
            'accept': 'application/json',
        }
        response = requests.post(
            url,
            cert=(self.certPath, self.keyPath),
            headers=headers
        )
        if response.status_code == 200:
            logging.info("PING was successful!")
            return response.json()
        else:
            return {"Error": f"{response.text}"}

    def openDay(self, fiscalDayNo: int)->dict:
        '''
        Parameters:
        fiscalDayNo: int
        fiscalDayOpened: datetime.datetime, default=datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        this function checks that the state of the day is closed first, then it sends a request to the server to open the day
        
        if successful, updates the fiscalDayNo with the response data and returns the following example data:
        {
            'fiscalDayNo': 2, 
            'operationID': '0HN4FDK6T1CNI:00000001'
        }
        '''
        # Refresh operating mode and ensure we are not in Offline-only mode (openDay requires online mode per spec)
        self.refresh_operating_mode()

        fiscalDayOpened = datetime.now().strftime('%Y-%m-%dT%H:%M:%S')
        #check if the day is closed
        status = self.getStatus()
        if isinstance(status, dict) and status.get('fiscalDayStatus') and status.get('fiscalDayStatus') != 'FiscalDayClosed':
            return {"error": f"Fiscal Day {status.get('lastFiscalDayNo')} is not closed"}
        
        #check if day being requested to be opened is later than the last day closed
        if isinstance(status, dict) and status.get('lastFiscalDayNo') is not None:
            if fiscalDayNo <= status['lastFiscalDayNo']:
                return {"error": f"Fiscal Day being opened: day {fiscalDayNo} is earlier than the last closed day: day {status['lastFiscalDayNo']}"}

            
        url = f'{self.deviceBaseUrl}/OpenDay'
        headers = {
            'DeviceModelName': self.deviceModelName,
            'DeviceModelVersion': self.deviceModelVersion,
            'accept': 'application/json',
            'Content-Type': 'application/json'
        }
        payload = {
            "fiscalDayNo": fiscalDayNo,
            "fiscalDayOpened": fiscalDayOpened
        }
        
        try:
            response = requests.post(
                url, 
                cert=(self.certPath, self.keyPath),
                headers=headers, 
                json=payload
                )
            response.raise_for_status()  # Will raise an HTTPError for bad responses
            data = response.json()
            return data

        except requests.exceptions.RequestException as e:
            return {"error": f"HTTP request failed: {e}"}
        except ValueError:
            return {"error": "Invalid JSON response"}

    def prepareReceipt(self, receiptData: dict, previousReceiptHash = None) -> dict:
        '''
        Level: Critical
        This function extracts required information from a receipt reliably and formats it 
        for the submitReceipt method.
        '''
        
        def receiptlinesfixer(receipt: dict) -> dict:
            """
            Fixes the receipt lines to conform with what the ZIMRA API accepts.
            newly added HS codes, if no HS codes are present in the presented receipt we are adding
            the default HS code 04021099
            """
            def taxID(line):
                tax_percent = float(line['tax_percent'])
                if int(tax_percent) == 0:
                    return 2
                elif tax_percent == 5:
                    return 1
                elif tax_percent == 15:
                    return 3
                else:
                    raise ValueError(f"Invalid tax_percent value: {tax_percent}")
                
            receiptlines = receipt['receiptLines']
            output_receipt_lines = []

            for i, line in enumerate(receiptlines):
                fixed_line = {
                    'receiptLineType': 'Sale',
                    'receiptLineNo': i + 1,
                    'receiptLineHSCode': '04021099' if 'hs_code' not in line else line['hs_code'],
                    'receiptLineName': line['item_name'],
                    'receiptLinePrice': line['unit_price'],
                    'receiptLineQuantity': line['quantity'],
                    'receiptLineTotal': float(line['quantity']) * float(line['unit_price']),
                    'taxPercent': line['tax_percent'],
                    'taxID': taxID(line)
                }
                output_receipt_lines.append(fixed_line)
                
            receipt["receiptLines"] = output_receipt_lines
            return receipt

        def taxlines_fixer(receipt: OrderedDict) -> OrderedDict:
            """
            Takes in the receipt after the receiptLinesFixer function.
            Inserts consolidated tax lines into the receipt after the receiptLines.
            basically this function does the actual taxes so take your time on it. 
            """
            receipt_with_taxlines = OrderedDict()
            for key, value in receipt.items():
                receipt_with_taxlines[key] = value
                # we copy all the fields from the previous receipt until we get to the receiptLines part after which we need to inject
                if key == "receiptLines":
                    tax_lines = defaultdict(lambda: {"taxAmount": 0, "salesAmountWithTax": 0})
                    for item in receipt["receiptLines"]:
                        tax_percent = round(float(item["taxPercent"]),2) # should be a float with up to 2 decimal places
                        tax_id = int(item["taxID"]) # should be an integer 
                        tax_lines[(tax_percent, tax_id)]["taxAmount"] += self.tax_calculator(item["receiptLineTotal"], tax_percent)
                        tax_lines[(tax_percent, tax_id)]["salesAmountWithTax"] += item["receiptLineTotal"]
                        tax_lines[(tax_percent, tax_id)]["taxPercent"] = tax_percent
                        tax_lines[(tax_percent, tax_id)]["taxID"] = tax_id
                    receipt_with_taxlines["receiptTaxes"] = [
                        {
                            "taxPercent": float("{:.2f}".format(float(key[0]))),
                            "taxID": key[1],
                            "taxAmount": self.tax_calculator(sale_amount=value["salesAmountWithTax"], tax_rate=float("{:.2f}".format(float(key[0])))),
                            "salesAmountWithTax": value["salesAmountWithTax"]
                        }
                        for key, value in tax_lines.items()
                    ]
            return receipt_with_taxlines

        def insert_receiptDeviceSignature(receiptData: OrderedDict, previous_hash=previousReceiptHash)-> OrderedDict:
            """
            this is the final nail in the coffin before sending receipt to zimra
            """
 
            receiptTaxes = receiptData["receiptTaxes"]
            concatenated_receipt_taxes = self.concatenate_receipt_taxes(receiptTaxes=receiptTaxes)  
            if previous_hash:
                string_to_sign = f"{self.deviceID}{receiptData['receiptType'].upper()}{receiptData['receiptCurrency'].upper()}{receiptData['receiptGlobalNo']}{receiptData['receiptDate']}{int(receiptData['receiptTotal']*100)}{concatenated_receipt_taxes}{previous_hash}"
                logging.info(f"Library Info: string to sign: {string_to_sign}")
            else:
                string_to_sign = f"{self.deviceID}{receiptData['receiptType'].upper()}{receiptData['receiptCurrency'].upper()}{receiptData['receiptGlobalNo']}{receiptData['receiptDate']}{int(receiptData['receiptTotal']*100)}{concatenated_receipt_taxes}"
                logging.info(f"Library Info: string to sign: {string_to_sign}")
                
            hash_value = self.get_hash(string_to_sign)
            signature = self.sign_data(string_to_sign)
            receiptData["receiptDeviceSignature"] = {
                "hash": hash_value,
                "signature": signature
            }
            
            return receiptData
            
        # Mandatory fields
        mandatory_fields = [
            "receiptType",        # "FISCALINVOICE",  | "CREDITNOTE" | "DEBITNOTE"
            "receiptCurrency",    # USD | ZiG
            "receiptCounter",     # integer
            "receiptGlobalNo",    # integer
            "invoiceNo",          # unique string
            "receiptDate",        # datetime (format as %Y-%m-%dT%H:%M:%S)
            "receiptLines",       # items (list of sold items)
            "receiptPayments",        # "CASH" | "CARD" and their totals (placed as objects)
        ]

        # Optional fields, can exist or not
        optional_fields = [
            "buyerData",          # Optional buyer info
            "creditDebitNote",     # only mandatory credit/debit note
            "receiptNotes"
        ]

        # Extracting mandatory fields, raising an error if missing
        prepared_receipt = OrderedDict()
        if receiptData['receiptType'].lower() in ['creditnote', 'debitnote']:
            mandatory_fields.append('receiptNotes')
            mandatory_fields.append('creditDebitNote')
        
        for field in mandatory_fields:
            if field not in receiptData:
                raise ValueError(f"Library Error: Missing mandatory field: {field}")
            
            prepared_receipt[field] = receiptData[field]

        # Formatting receiptDate to the required format
        if isinstance(prepared_receipt['receiptDate'], datetime):
            prepared_receipt['receiptDate'] = prepared_receipt['receiptDate'].strftime('%Y-%m-%dT%H:%M:%S')
        elif isinstance(prepared_receipt['receiptDate'], str):
            # Check if the date is in the correct format
            try:
                # Parse and format back to ensure consistent output
                prepared_receipt['receiptDate'] = datetime.strptime(prepared_receipt['receiptDate'], '%Y-%m-%dT%H:%M:%S').strftime('%Y-%m-%dT%H:%M:%S')
            except ValueError:
                # Handle cases with milliseconds (e.g., "2024-11-06T15:47:14.495Z")
                try:
                    prepared_receipt['receiptDate'] = datetime.strptime(prepared_receipt['receiptDate'][:-5], '%Y-%m-%dT%H:%M:%S').strftime('%Y-%m-%dT%H:%M:%S')
                    logging.info(f"Library Info: Manually formatted date: {prepared_receipt['receiptDate']}")
                except ValueError:
                    raise ValueError("Library Error: Invalid receiptDate format. Must match 'YYYY-MM-DDTHH:MM:SS' or similar.")
        else:
            raise ValueError("Library Error: Invalid receiptDate format. Must be a string or datetime object.")

        # Insert receiptLinesTaxInclusive right after receiptDate
        prepared_receipt['receiptLinesTaxInclusive'] = True

        # Compute the total
        prepared_receipt['receiptTotal'] = sum([float(line['unit_price']) * float(line['quantity']) for line in receiptData['receiptLines']])

        # Extracting optional fields if present
        for field in optional_fields:
            if field in receiptData:
                prepared_receipt[field] = receiptData[field]

        # Reorder the dictionary to place receiptLinesTaxInclusive after receiptDate
        
        # THE MAGIC IS HAPPENING HERE
        reordered_receipt = OrderedDict()
        for key in list(prepared_receipt.keys()):
            reordered_receipt[key] = prepared_receipt[key]
            if key == "receiptDate":
                reordered_receipt["receiptLinesTaxInclusive"] = True
        reordered_receipt = receiptlinesfixer(reordered_receipt)
        reordered_receipt = taxlines_fixer(receipt=reordered_receipt)
        if reordered_receipt['receiptTotal'] != reordered_receipt['receiptPayments'][0]['paymentAmount']:
            logging.info(f"Library Error: Receipt total ({reordered_receipt['receiptTotal']}) does not match payment amount ({reordered_receipt['receiptPayments'][0]['paymentAmount']}).\n fixing that though")
            reordered_receipt['receiptTotal']=float(reordered_receipt['receiptPayments'][0]['paymentAmount'])
        reordered_receipt = insert_receiptDeviceSignature(receiptData=reordered_receipt)
        return reordered_receipt

    def submitReceipt(self, receiptData:dict)->dict:
        '''
        Level: Critical
        uses self.deviceID and receipt data to submit receipt
        the method refreshes deviceOperatingMode and then submits receipt
        '''

        # Refresh and ensure device is allowed to submit receipts in current mode
        self.refresh_operating_mode()

        if self.deviceOperatingMode and str(self.deviceOperatingMode).lower() == 'offline':
            # According to spec, SubmitReceipt can't be sent if DeviceOperatingMode is Offline.
            return {"error": "Device operating mode is Offline. SubmitReceipt is not allowed in Offline mode (DEV01)."}

        url = f'{self.deviceBaseUrl}/SubmitReceipt'
        headers = {
            'DeviceModelName': self.deviceModelName,
            'DeviceModelVersion': self.deviceModelVersion,
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }

        fields = [
            "receiptType", # string "FISCALINVOICE" | "CREDITNOTE" | "DEBITNOTE"
            "receiptCurrency", # string USD|ZiG
            "receiptCounter", # int
            "receiptGlobalNo", # int
            "invoiceNo", # unique string
            "buyerData",
            "receiptNotes",
            "receiptDate", # datetime formatted by strftime('%Y-%m-%dT%H:%M:%S')
            "creditDebitNote",
            "receiptLinesTaxInclusive", # boolean
            "receiptLines", # list of receiptlineType objects
            "receiptTaxes", # list of tax objects
            "receiptPayments", # list of payment objects
            "receiptTotal", # float not in cents
            "receiptPrintForm",
            "receiptDeviceSignature" # string base64 encoded dictionary of hash and signature
        ]

        # Build the payload dynamically
        payload = {
            "Receipt": {key: receiptData[key] for key in fields if key in receiptData}
        }
        logging.info(f"==== RECEIPT SENT\n\n{(json.dumps(payload, indent=4))}")

        
        response = requests.post(
            url,
            cert=(self.certPath, self.keyPath),
            headers=headers,
            json=payload
        )
        
        if response.status_code == 200:
            data = response.json()
            return data
        else:
            # return response information consistent with existing library style
            response_object = {response.status_code: response.text}
            return response_object
            
    def submitFile(self, file_json: dict, filename: str = "file.json") -> dict:
        """
        Submit a batch file (header, content, footer) to FDMS.
        The file must be a JSON object (dict) with "header" and optional "content" and "footer".
        The JSON is base64-encoded and sent as multipart/form-data under the 'file' field.
        Enforces Offline-only rule (refreshes deviceOperatingMode before sending).
        """
        # Refresh operating mode per Option A
        self.refresh_operating_mode()

        # Enforce Offline mode requirement
        if self.deviceOperatingMode and str(self.deviceOperatingMode).lower() != 'offline':
            return {"error": "Device operating mode is not Offline. submitFile can only be sent in Offline mode (DEV01)."}

        # prepare base64 content
        try:
            # Ensure compact encoding to reduce size
            json_bytes = json.dumps(file_json, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            b64_bytes = base64.b64encode(json_bytes)
        except Exception as e:
            logging.error(f"Failed to encode file json: {e}")
            return {"error": f"Failed to encode file json: {e}"}

        # Check size limit: 3 MB
        max_size = 3 * 1024 * 1024  # 3 MB
        if len(b64_bytes) > max_size:
            return {"error": f"Encoded file too large: {len(b64_bytes)} bytes (max {max_size}). Split the file into smaller chunks."}

        url = f"{self.deviceBaseUrl}/SubmitFile"

        files = {
            # ('filename', fileobj, content_type)
            "file": (filename, b64_bytes, "application/octet-stream")
        }

        headers = {
            'DeviceModelName': self.deviceModelName,
            'DeviceModelVersion': self.deviceModelVersion
            # Do not set Content-Type for multipart; requests will set it.
        }

        try:
            response = requests.post(
                url,
                cert=(self.certPath, self.keyPath),
                files=files,
                headers=headers,
                timeout=60
            )
            # Accept 200 or 202 as success depending on server behavior
            if response.status_code in (200, 202):
                try:
                    return response.json()
                except Exception:
                    return {"status_code": response.status_code, "text": response.text}
            else:
                logging.error(f"submitFile failed: {response.status_code} - {response.text}")
                return {response.status_code: response.text}
        except requests.exceptions.RequestException as e:
            logging.error(f"submitFile HTTP error: {e}")
            return {"error": str(e)}

    def getFileStatus(self, fileUploadedFrom: str = None, fileUploadedTill: str = None, operationID: str = None):
        """
        Query FDMS for previously uploaded file statuses.
        Parameters:
            fileUploadedFrom: 'YYYY-MM-DD' (required unless operationID provided)
            fileUploadedTill: 'YYYY-MM-DD' (required unless operationID provided)
            operationID: optional operationID returned by submitFile
        """
        # Refresh operating mode (per Option A)
        self.refresh_operating_mode()

        # Per spec, GetFileStatus is allowed in Offline mode only.
        if self.deviceOperatingMode and str(self.deviceOperatingMode).lower() != 'offline':
            return {"error": "Device operating mode is not Offline. getFileStatus can only be called in Offline mode (DEV01)."}

        url = f"{self.deviceBaseUrl}/GetFileStatus"
        params = {}
        if operationID:
            params["operationID"] = operationID
        else:
            # fileUploadedFrom and fileUploadedTill mandatory if operationID not provided
            if not fileUploadedFrom or not fileUploadedTill:
                return {"error": "fileUploadedFrom and fileUploadedTill are required if operationID is not provided."}
            params["fileUploadedFrom"] = fileUploadedFrom
            params["fileUploadedTill"] = fileUploadedTill

        try:
            response = requests.get(
                url,
                cert=(self.certPath, self.keyPath),
                headers={
                    'DeviceModelName': self.deviceModelName,
                    'DeviceModelVersion': self.deviceModelVersion
                },
                params=params,
                timeout=30
            )
            if response.status_code == 200:
                return response.json()
            else:
                logging.error(f"getFileStatus failed: {response.status_code} - {response.text}")
                return {response.status_code: response.text}
        except requests.exceptions.RequestException as e:
            logging.error(f"getFileStatus HTTP error: {e}")
            return {"error": str(e)}

    def generate_qr_code(self, signature: str, receipt_global_no, receipt_date=datetime.now().date()):
        """
        Parameters:
        signature(str): receipt signature
        receipt_global_no(int): receipt global number
        receipt_date = type(datetime.datetime.now().date())
        """
        import base64
        import hashlib


        def get_first16chars_of_signature(signature: str)->str:
            """
            Returns first 16 chars of the md5 hash of the signature by first converts from base64 to hex, then from hex to md5

            Parameters: 
            signature(str): receipt signature

            Returns:
            str: first 16 chars of the md5 hash of the signature
            """
            if not isinstance(signature, str) or not signature:
                raise ValueError("Input must be a non-empty string.")

            try:
                # Decode Base64 string to bytes
                byte_array = base64.b64decode(signature)
            except (ValueError, base64.binascii.Error) as e:
                raise ValueError("Invalid Base64 string.") from e

            # Convert bytes to a hexadecimal string
            hex_str = byte_array.hex()

            # Compute MD5 hash of the hexadecimal string
            md5_hash = hashlib.md5(bytes.fromhex(hex_str)).hexdigest()

            # Return the first 16 characters of the MD5 hash
            return md5_hash[:16]

        def generate_qr_code_string(device_id, receipt_date, receipt_global_no, receipt_device_signature, qr_url):
            device_id = str(self.deviceID).zfill(10)
            receipt_date = receipt_date.strftime('%d%m%Y')
            receipt_global_no = str(receipt_global_no).zfill(10)
            md5_hash = receipt_device_signature
            qr_value = f"{qr_url}{device_id}{receipt_date}{receipt_global_no}{md5_hash}"
            return qr_value

        receipt_device_signature = get_first16chars_of_signature(signature) # signature fetched from dynamic source

        qr_code_value = generate_qr_code_string(
            device_id=self.deviceID, 
            receipt_date=receipt_date, 
            receipt_global_no=receipt_global_no, 
            receipt_device_signature=receipt_device_signature, 
            qr_url=self.qrUrl
        )

        return qr_code_value

    def closeDay(self, fiscalDayNo: int, fiscalDayDate, lastReceiptCounterValue: int, fiscalDayCounters: list):
        '''
        #string_to_sign = f'{device_id}{fiscal_day_no}{fiscal_day_date}{fiscalCounterType|fiscalCounterCurrency|fiscalCounterTaxID}'
        example, to close an empty day (day 17)for device 10626 on 2024-09-02:
            string_to_implement = '10626172024-09-02'
            hash = get_hash(string_to_implement)
            signature = sign_data(data=hash, private_key_pem=private_key_pem)
        '''
        # Refresh operating mode per Option A
        self.refresh_operating_mode()

        # closeDay requires Online mode (spec: request can't be sent if DeviceOperatingMode is Offline)
        if self.deviceOperatingMode and str(self.deviceOperatingMode).lower() == 'offline':
            return {"error": "Device operating mode is Offline. closeDay is not allowed in Offline mode (DEV01)."}

        if lastReceiptCounterValue==None or fiscalDayCounters==None or fiscalDayCounters==[]:
            lastReceiptCounterValue = 0
            string_to_implement = f'{self.deviceID}{fiscalDayNo}{fiscalDayDate}'
        
        def generate_string(device_id, fiscal_day_no, fiscal_day_date, fiscal_day_counters):
            # Mapping for fiscalCounterMoneyType
            money_type_mapping = {
                0: "CASH",
                1: "CARD",
                2: "MOBILEWALLET",
                3: "COUPON",
                4: "CREDIT",
                5: "BANKTRANSFER",
                6: "OTHER"
                
            }
            # Sort the fiscalDayCounters as per the rules
            sorted_counters = sorted(
                fiscal_day_counters,
                key=lambda x: (
                    # Priority based on fiscal counter type
                    1 if x['fiscalCounterType'] == 'SaleByTax' else
                    2 if x['fiscalCounterType'] == 'SaleTaxByTax' else
                    3 if x['fiscalCounterType'] == 'CreditNoteByTax' else
                    4 if x['fiscalCounterType'] == 'CreditNoteTaxByTax' else
                    5 if x['fiscalCounterType'] == 'DebitNoteByTax' else
                    6 if x['fiscalCounterType'] == 'DebitNoteTaxByTax' else
                    7 if x['fiscalCounterType'] == 'BalanceByMoneyType' else 99,
                    # Sort alphabetically by fiscal counter currency
                    x['fiscalCounterCurrency'],
                    # Sort by fiscal counter tax ID (if present) or fiscal counter money type
                    x.get('fiscalCounterTaxID', ''),
                    x.get('fiscalCounterMoneyType', '')
                )
            )
            # Concatenate the sorted fiscalDayCounters
            concatenated_counters = ''.join(
                f"{counter['fiscalCounterType'].upper()}"
                f"{counter['fiscalCounterCurrency'].upper()}"
                f"{'{:.2f}'.format(counter['fiscalCounterTaxPercent']) if counter.get('fiscalCounterTaxPercent') is not None else ''}"
                f"{money_type_mapping.get(counter.get('fiscalCounterMoneyType'), '')}"  # Map money type to string
                f"{int(float(counter['fiscalCounterValue']) * 100)}"  # Convert to cents
                for counter in sorted_counters
                if float(counter['fiscalCounterValue']) != float(0)
            )
            # Final string
            logging.info(f"Concatenated Counters===================: {concatenated_counters}")
            string_to_implement = f"{device_id}{fiscal_day_no}{fiscal_day_date}{concatenated_counters}"
            return string_to_implement

        def get_hash(request):
            hash_object = hashlib.sha256(request.encode('utf-8'))
            return base64.b64encode(hash_object.digest()).decode('utf-8')

        def sign_data(data, private_key_pem):
            if data is None:
                data = ""
            key = RSA.import_key(private_key_pem)
            h = SHA256.new(data.encode('utf-8'))
            signature = pkcs1_15.new(key).sign(h)
            return base64.b64encode(signature).decode('utf-8')
        
        
        fiscalDayCounters = convert_objectid_to_str(fiscalDayCounters)
        if fiscalDayCounters!=[]:
            string_to_implement = generate_string(self.deviceID, fiscalDayNo, fiscalDayDate, fiscalDayCounters)
        else:
            string_to_implement = f'{self.deviceID}{fiscalDayNo}{fiscalDayDate}'
        
        logging.info(f"STRING TO IMPLEMENT CLOSE DAY:------:{string_to_implement}")
        hash_value = get_hash(string_to_implement)
        with open(self.keyPath, 'rb') as key_file:
            private_key_pem = key_file.read()
        fDSSignature = sign_data(string_to_implement, private_key_pem)
        
        url = f'{self.deviceBaseUrl}/CloseDay'
        headers = {
            'accept': 'application/json',
            'Content-Type': 'application/json'
        }
        if hasattr(self, 'deviceModelName'):
            headers['DeviceModelName'] = self.deviceModelName
        
        if hasattr(self, 'deviceModelVersion'):
            headers['DeviceModelVersion'] = self.deviceModelVersion

        

        payload = {
            "deviceID": self.deviceID,
            "fiscalDayNo": fiscalDayNo,
            "fiscalDayCounters": fiscalDayCounters,
            "fiscalDayDeviceSignature": {
                "hash": hash_value,
                "signature": fDSSignature
            },
            "receiptCounter": lastReceiptCounterValue
        }

        logging.info(f"CLOSE DAY Payload===================: {payload}")

        

        try:
            response = requests.post(
                url, 
                headers=headers,
                cert=(self.certPath, self.keyPath),
                json=payload
            )
            logging.info(f"Response from Zimra======: {response.json()}")
            response.raise_for_status() 
            data = response.json()
            logging.info(string_to_implement)
            return data
            

        except requests.exceptions.RequestException as e:
            return f"HTTP request failed: {e}"
        except ValueError:
            return f"Invalid JSON response"
        
