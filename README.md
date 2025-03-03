# BUREAU-REPORT-API-ANALYSIS

# TransUnion API to Excel Report Automation

Tired of spending hours manually analyzing credit reports? Automate the process with this solution! Instantly retrieve credit data from Bureau APIs and generate an easy-to-read Excel file with just a few clicks. Save time, eliminate errors, and streamline your credit analysis workflow!

## Features
- **Automated API Data Fetching**: Pull data directly from TransUnion's Bureau API.
- **Effortless Credit History Parsing**: Get neatly formatted credit data in seconds.
- **DPD Highlights**: Automatically detect overdue accounts and display "Days Past Due" (DPD) counts.
- **CAM Details**: Generate a comprehensive financial summary for credit application and monitoring.

## How It Works
### 1. API Call and Data Fetching
The script sends an encrypted request to the TransUnion Bureau API, retrieves the consumer's credit data, and decrypts the response.

### 2. Data Parsing and Processing
The credit history data is processed and formatted into a clean, readable structure:
- Names, Telephones, and Addresses
- Account details
- Payment history and inquiries

### 3. Excel Sheet Generation
- **Credit History Sheet**: Displays the consumer's credit report in a simplified format.
- **DPD Highlights Sheet**: Shows overdue payments, highlighting accounts with "Days Past Due."
- **CAM Details Sheet**: Summarizes account types, payment history, and loan information for a clear financial picture.

## Dependencies
- **Python 3.x**
- `paramiko` - SFTP handling
- `requests` - API requests
- `pandas` - Data manipulation and Excel output
- `psycopg2` - PostgreSQL database connectivity
- `Crypto` - For encryption/decryption of API payloads
- `thefuzz` - Data matching and cleaning

Install all dependencies with:
```bash
pip install paramiko requests pandas psycopg2 thefuzz pycryptodome
```

## Configuration
1. **Important**: The provided credentials, URLs, API keys, and database details in the script are **placeholders**. Replace them with your actual credentials.
2. Set the correct file paths for input, processed, and output data.

## Running the Script
To execute:
```bash
python automation.py
```


## Output
The script generates an Excel file with three sheets:

1. **Credit History**: A well-structured credit report.
2. **DPD Highlights**: Summarizes defaulted accounts and overdue payments.
3. **CAM Details**: Provides a detailed analysis of credit applications, loan summaries, and account performance. The conditions and analysis criteria for this sheet can be customized based on your specific preferences.

