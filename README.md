# 📊 ICI Report Export

This Python script is designed to export reports by fetching data from the ICI API and processing it. The script includes functionalities for argument parsing, logging, and data validation.

## 📋 Table of Contents
- [📊 ICI Report Export](#-ici-report-export)
  - [📋 Table of Contents](#-table-of-contents)
  - [🚀 Features](#-features)
  - [🔧 Installation](#-installation)
  - [⚙️ Usage](#️-usage)
    - [Arguments](#arguments)
    - [Example Commands](#example-commands)
  - [🧪 Testing](#-testing)
  - [📜 Licence](#-licence)

## 🚀 Features
- Argument parsing for specifying date ranges and report patterns.
- Logging of script execution start times.
- Validation of date formats.
- Fetching and processing data from the ICI API.
- Generating report excels.

## 🔧 Installation
Requirements:
- Python 3.10 or higher

1. Clone the repository:
   ```bash
   git clone https://github.com/eastgenomics/ici_reports_export.git
   cd ici_reports_export
   ```

2. Create a virtual environment and activate it:
   ```bash
   python -m venv venv
   source venv/bin/activate
   ```

3. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## ⚙️ Usage
The script can be run in different modes based on the provided arguments. Below are the possible inputs and examples for each argument:

### Arguments
- `--created_before`: The end date for the data to be fetched. Format: `YYYY-MM-DD'T'HH:MM:SS'Z'`. Example: `2024-01-01T08:30:00Z`
- `--created_after`: The start date for the data to be fetched. Format: `YYYY-MM-DD'T'HH:MM:SS'Z'`. Example: `2023-01-01T08:30:00Z`

### Example Commands
1. Run the script with required arguments:
   ```bash
   python generate_report_excels.py --created_before 2024-01-01T08:30:00Z --created_after 2023-01-01T08:30:00Z
   ```

## 🧪 Testing
1. Install `pytest`:
   ```bash
   pip install pytest
   ```

2. Run the tests:
   ```bash
   pytest tests/test_generate_report_excels.py
   ```

## 📜 Licence
This project is licenced under the MIT Licence. See the [LICENCE](LICENCE) file for details.
