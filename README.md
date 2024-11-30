# SAML Data Processor

This tool decodes Base64-encoded SAML data and offers functionalities to extract email addresses and perform string replacements within the decoded content.

## Features

- **Extract Emails**: Searches for and extracts email addresses from decoded data.
- **Replace Strings**: Replaces specified strings within the decoded data and re-encodes the result to Base64.

## Prerequisites

- Python 3.x

## Installation

Clone this repository to your local machine:

```bash
git clone <repository-url>
cd <repository-directory>
```

## Usage
Run the script with the required commands to process your SAML data:

#### To extract emails from a Base64-encoded file:
```bash
python3 saml_tool.py --extract <file_path>
```

#### To replace a specific string in the decoded data:
```bash
python3 saml_tool.py --replace <old_string> <new_string> <file_path>
```

##### To strip signature in between `<ds:SignatureValue></ds:SignatureValue>` tags
```bash
python3 saml_tool.py --strip-signature-value <file_path>
```