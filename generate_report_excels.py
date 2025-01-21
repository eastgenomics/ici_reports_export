"""
This script fetches audit logs from the ICI API, filters the logs based on
specific event types (to get case IDs for recent reports ina  time-period),
and extracts reports JSONS. The script then processes the reports
to extract relevant information and generates
an Excel file with the extracted data.
"""
# Stdlib imports
import os
import re
import logging
import datetime as dt
from venv import logger

# Third-party imports
import requests
import argparse
import dotenv
import pandas as pd
import shutil

# Setup logging
logging.basicConfig(
    filename='ici_api_script.log',
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)


def parse_args():
    """
    Import arguments from the command line.

    Parameters
    ----------
    None

    Returns
    -------
    args : argparse.Namespace
        The arguments from the command line.
    """
    parser = argparse.ArgumentParser(
        description='Determine runtime mode and other parameters.')
    parser.add_argument('--mode', type=str, choices=['manual', 'cron'], required=True,
                        help='Runtime mode: "manual" or "cron".')
    parser.add_argument('--created_before', type=str, default=None,
                        help='The date string in the format YYYY-MM-DD\'T\'HH:MM:SS\'Z\''
                        'e.g: 2024-01-01T08:30:00Z to filter reports created before this date. Only allowed in manual mode.')
    parser.add_argument('--created_after', type=str, default=None,
                        help='The date string in the format YYYY-MM-DD\'T\'HH:MM:SS\'Z\''
                        'e.g: 2024-01-01T08:30:00Z to filter reports created after this date. Only allowed in manual mode.')
    args = parser.parse_args()
    # Validate inputs
    if args.created_before == "" or args.created_after == "":
        logging.error(
            "Invalid date format for created_before or created_after.")
        raise SystemExit
    if args.created_before and args.created_after:
        if args.created_before <= args.created_after:
            logging.error(
                "created_before date should be greater than created_after date.")
            raise SystemExit
    if args.created_before:
        try:
            # Check if the date is in the correct format
            # Format YYYY-MM-DD'T'HH:MM:SS'Z'
            if args.created_before == "":
                logging.error("Invalid date format for created_before: %s",
                              args.created_before)
                raise SystemExit
            dt.datetime.strptime(args.created_before, "%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            logging.error("Invalid date format for created_before: %s",
                          args.created_before)
            raise SystemExit
    if args.created_after:
        try:
            # Check if the date is in the correct format
            # Format YYYY-MM-DD'T'HH:MM:SS'Z'
            if args.created_after == "":
                logging.error("Invalid date format for created_before: %s",
                              args.created_before)
                raise SystemExit
            dt.datetime.strptime(args.created_after, "%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            logging.error("Invalid date format for created_after: %s",
                          args.created_after)
            raise SystemExit
    return args


def log_start_time(start_time_file):
    """
    Log the start time of the script execution and store it in a file.

    Parameters
    ----------
    start_time_file : str
        The file name to store the start time.

    Returns
    -------
    tuple
        A tuple containing the previous start time and the current start time.
    """
    #start_time_file = 'script_start_time.log'
    current_start_time = dt.datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")

    # Read the previous start time from the file
    if os.path.exists(start_time_file):
        with open(start_time_file, 'r') as file:
            previous_start_time = file.read().strip()
    else:
        previous_start_time = None
        raise RuntimeError(
            "Script start time file not found. Required to run the script."
        )

    # Validate the previous start time
    if previous_start_time:
        try:
            dt.datetime.fromisoformat(previous_start_time)
        except ValueError:
            logging.warning(
                "Invalid previous start time format in the log file.")
            previous_start_time = None

    # Write the current start time to the file
    with open(start_time_file, 'w') as file:
        file.write(current_start_time)

    logging.info("Script start time recorded: %s", current_start_time)
    return previous_start_time, current_start_time


def setup_api(api_key, x_illumina_workgroup):
    """
    Setup the API headers for the request.

    Parameters
    ----------
    api_key : str
        The API key for the ICI API.
    x_illumina_workgroup : str
        The workgroup for the ICI API.

    Returns
    -------
    headers : dict
        The headers for the API request, including authentication.
    """
    headers = {
        'accept': '*/*',
        'Authorization': f'ApiKey {api_key}',
        'X-ILMN-Domain': 'eval-uki',
        'X-ILMN-Workgroup': f'{x_illumina_workgroup}',
    }
    return headers


def get_audit_logs(base_url, headers, event_name, endpoint,
                   created_before=None, created_after=None, page_size=1000):
    """
    Fetch audit logs for specific event types from the ICI API.

    Parameters
    ----------
    base_url : str
        The base URL for the ICI API.
    headers : dict
        The headers for the API request, including authentication.
    event_name : str
        The name of the event to filter audit logs.
        i.e. "case.status.updated" or "case.report.added"
    endpoint : str
        The ICI API endpoint to fetch audit logs.
        i.e. als/api/v1/auditlogs/search
    created_before : str
        The date string in the format YYYY-MM-DD'T'HH:MM:SS'Z'
        e.g: 2024-01-01T08:30:00Z to filter reports created before this date.
    created_after : str
        The date string in the format YYYY-MM-DD'T'HH:MM:SS'Z'
        e.g: 2024-01-01T08:30:00Z to filter reports created after this date.
    page_size : int
        The number of audit logs to fetch per page.

    Returns
    -------
    list
        A list of audit log entries, each represented as a dictionary.
        If an error occurs, returns an empty list.

    Examples
    --------
    >>> logs = get_audit_logs("https://api.ici.example.com", headers,
                              "case.report.added", "als/api/v1/auditlogs/search")
    """
    logging.info("Fetching audit logs from ICI API.")
    url = f"{base_url}{endpoint}"
    params = {
        "eventName": event_name,
        "toDate": created_before,
        "fromDate": created_after,
        "pageNumber": 0,
        "pageSize": page_size
    }

    try:
        response = requests.get(url, headers=headers, params=params)
        logging.debug("Audit logs response: %s", response.json())
        return response.json().get("content", [])
    except requests.exceptions.RequestException as e:
        logging.error("Error fetching audit logs: %s", e)
        raise RuntimeError("Error fetching audit logs. See Logs.")


def get_report(base_url, headers, case_id):
    """
    Fetch the report for a specific case ID from the ICI API.

    Parameters
    ----------
    base_url : str
        The base URL for the ICI API.
    headers : dict
        The headers for the API request, including authentication.
    case_id : str
        The case ID for which the report is to be fetched.

    Returns
    -------
    dict or None
        The report JSON object if the request is successful, otherwise None.

    Examples
    --------
    >>> report = get_report("https://api.ici.example.com", headers, "12345")
    >>> report["status"]
    'completed'
    """
    logging.info("Fetching report for case ID: %s", case_id)
    url = f"{base_url}drs/v1/draftreport/case/{case_id}/reportjson"

    try:
        print(url, headers)
        response = requests.get(url, headers=headers)
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error("Error fetching report for case %s: %s", case_id, e)
        return None


def process_reports_and_generate_excel(audit_logs,
                                       base_url,
                                       headers,
                                       report_pattern,
                                       ):
    """
    Process audit logs to fetch reports and generate an Excel file.

    Parameters
    ----------
    audit_logs : list
        A list of audit log entries, each represented as a dictionary.
        The logs are filtered and matched to fetch corresponding reports.
    base_url : str
        The base URL for the ICI API.
    headers : dict
        The headers for the API request, including authentication.
    report_pattern : str
        The regex pattern to match in the report text.

    Returns
    -------
    None
        Generates an Excel file named 'output.xlsx' if matched reports are found.

    Examples
    --------
    >>> logs = get_audit_logs("https://api.ici.example.com", headers,
                              "case.report.added", "als/api/v1/auditlogs/search")
    >>> process_reports_and_generate_excel(logs, "https://api.ici.example.com",
                                           headers, "regex_pattern")
    """
    logging.info("Processing audit logs and fetching reports.")
    matched_reports = []

    for log in audit_logs:
        case_id = log.get("caseId")
        print(case_id)
        # Assuming report text is in the 'message' field
        report_text = log.get("message", "")
        print(report_pattern)
        if re.search(report_pattern, report_text, re.IGNORECASE):
            logging.debug(
                "Report text matched pattern for case ID: %s", case_id)
            report_json = get_report(base_url, headers, case_id)
            print(report_json)
            if report_json:
                matched_reports.append(report_json)
        else:
            logging.debug("No match for case ID: %s", case_id)
            logging.debug("Report text: %s", report_text)
            logging.debug("Pattern: %s", report_pattern)

    if matched_reports:
        logging.info("Generating Excel file from matched reports.")

        for report in matched_reports:
            sample_id, case_info, snvs_variants_info, cnvs_variants_info, \
                indels_variants_info, tmb_msi_metric_info = (
                    extract_data_from_report_json(report)
                )
            json_extract_to_excel(
                sample_id, case_info, snvs_variants_info,
                cnvs_variants_info, indels_variants_info,
                tmb_msi_metric_info
            )
    else:
        logging.warning("No matched reports found to generate Excel.")

def extract_SNV_data(report_json):
    """
    Extract SNV data from the report JSON.

    Parameters
    ----------
    report_json : JSON object
        The JSON object containing information from the report API results.
    Returns
    -------
    snvs_variants_info : list
        A list of dictionaries containing variant information for SNV.
    """
    # SNVs
    snvs_variants_info = []
    report_data = report_json.get("reportData", {})
    findings = report_data.get("biomarkersFindings", {})
    print("No. findings:", len(findings))
    for finding in findings:
        # check for what variant
        variant_type = finding.get("value", "N/A")
        if "Copy Number Loss" in variant_type or "Copy Number Gain" in variant_type:
            variant_type = "CNV"
        elif "Insertion" in variant_type or "Deletion" in variant_type:
            variant_type = "Indel"
        elif "p." in variant_type:
            variant_type = "SNV"
        elif "TMB" or "MSI" in finding.get("name", "N/A"):
            variant_type = "TMB/MSI"
        else:
            variant_type = "N/A"
            print(finding)
            raise ValueError("Unknown variant type")
        # extract variant information for SNV
        if variant_type == "SNV":
            gene = finding.get("name", "N/A")
            consequence = ", ".join(finding.get(
                "variantTranscript", {}).get("consequences", ["N/A"]))
            transcript = finding.get(
                "variantTranscript", {}).get("name", "N/A")
            dna_nomenclature = finding.get(
                "variantTranscript", {}).get("hgvsc", "N/A")
            protein = finding.get("value", "N/A")
            vaf = finding.get("readFrequency", {})
            try:
                vaf = round(vaf, 2)
            except TypeError as e:
                print("Error: VAF calculation issue. See Error: %s", e)

            oncogenicity = ", ".join(
                [a.get("actionabilityName", "N/A") for a in finding.get("actionabilities", [])])

            variant_info = {
                "Gene": gene,
                "Consequences": consequence,
                "Transcript": transcript,
                "DNA Nomenclature": dna_nomenclature,
                "Protein": protein,
                "VAF": vaf,
                "Oncogenicity": oncogenicity,
            }
            snvs_variants_info.append(variant_info)
    return snvs_variants_info


def extract_CNV_indels_data(report_json):
    """
    Extract CNV and Indel data from the report JSON.

    Parameters
    ----------
    report_json : JSON object
        The JSON object containing information from the report API results.

    Returns
    -------
    cnvs_variants_info : list
        A list of dictionaries containing variant information for CNV.
    indels_variants_info : list
        A list of dictionaries containing variant information for Indel.
    """
    cnvs_variants_info = []
    indels_variants_info = []
    # Different logic for extracting CNV information
    # Extract relevant section of the JSON for CNV information
    report = report_json.get("subjects", [])
    if report:
        report = report[0]  # First and only element in the list
    else:
        raise RuntimeError("No subjects found in the report. Truncated JSON.")
    report = report.get("reports", [])
    if report:
        report = report[0]  # First and only element in the list
    else:
        raise RuntimeError("No reports found in the report. Truncated JSON.")
    try:
        variants = report.get("reportDetails", {}).get("variants", [])
    except AttributeError as e:
        print("Error: CNV variants not found. See Error: %s", e)
        variants = []
    # Extract CNV information
    for variant in variants:
        oncogenicity_list = []
        variant_type = variant.get("variantType", "Field not found")
        if variant_type is None or variant_type == "SNV":
            continue
        elif re.search(r"Copy Number (Loss|Gain)", variant_type):
            fold_change = variant.get("foldChange", "N/A")
            gene = variant.get("gene", "N/A")
            transcript = variant.get("transcript", {}).get("name", "N/A")
            for actionability in variant.get("associations", []):
                oncogenicity_list.append(actionability.get(
                    "associationInfo", {}).get("actionabilityName", None))
            oncogenicity_list = set(oncogenicity_list)
            oncogenicity = ", ".join(oncogenicity_list)
            variant_info = {
                "Gene": gene,
                "fold_change": fold_change,
                "Transcript": transcript,
                "Oncogenicity": oncogenicity,
            }
            cnvs_variants_info.append(variant_info)
        elif re.search(r"Insertion|Deletion|Delins|MNV", variant_type):
            gene = variant.get("gene", "N/A")
            print(variant.get("transcript", {}).get("consequences", ["N/A"]))
            consequences_list = list(variant.get(
                "transcript", {}).get("consequences", ["N/A"]))
            consequences_list = [x.get("consequence", None)
                                 for x in consequences_list]
            consequences = ", ".join(str(item) for item in consequences_list)
            transcript = variant.get("transcript", {}).get("name", "N/A")
            dna_nomenclature = variant.get(
                "transcript", {}).get("hgvsc", "N/A")
            protein = variant.get("transcript", {}).get("hgvsp", "N/A")
            vaf = variant.get("sampleMetrics", {})[0].get("vrf", "N/A")
            try:
                vaf = round(vaf, 2)
            except TypeError as e:
                print("Error: VAF calculation issue. See Error: %s", e)
            oncogenicity = ", ".join(
                [a.get("actionabilityName", "N/A") for a in variant.get("associations", [])])
            variant_info = {
                "Gene": gene,
                "Consequences": consequences,
                "Transcript": transcript,
                "DNA Nomenclature": dna_nomenclature,
                "Protein": protein,
                "VAF": vaf,
                "Oncogenicity": oncogenicity,
            }
            indels_variants_info.append(variant_info)
        else:
            logger.error(f"Unknown variant type: {variant_type}")
            logger.error(variant)
            raise ValueError("Unknown variant type")
    return cnvs_variants_info, indels_variants_info


def extract_TMB_MSI_data(report_json):
    """
    Extract TMB and MSI data from the report JSON.

    Parameters
    ----------
    report_json : JSON object
        The JSON object containing information from the report API results.

    Returns
    -------
    tmb_msi_metric_info : list
        A list of dictionaries containing metric information for TMB/MSI.
    """
    tmb_msi_metric_info = []
    # extract MSI and TMB metrics

    tmb_value, msi_value, msi_usable_sites, tmb_pct_exon_50X = "N/A", "N/A", "N/A", "N/A"

    # extract MSI and TMB metrics
    # from section which is always present in JSON
    report_data = report_json.get('reportData', {})
    tumor_sample = report_data.get('tumorSample', {})

    tmb_value = tumor_sample.get('tmb', 'N/A')
    msi_value = tumor_sample.get('msi', 'N/A')

    # useable sites for TMB and MSI
    qc_metrics = report_data.get("qcMetrics", {})
    for metric in qc_metrics:
        metric_name = metric.get("name", "")
        if metric_name == "DNA Library QC Metrics for MSI - Usable MSI Sites (Count)":
            msi_usable_sites = metric.get("value", "N/A")
        elif metric_name == "DNA Library QC Metrics for Small Variant Calling and TMB - % Exon 50X":
            tmb_pct_exon_50X = metric.get("value", "N/A")

    tmb_msi_variant_info = {
        "TMB (mut/MB)": tmb_value,
        "MSI (% unstable sites) ": msi_value,
        "MSI Total Usable Sites": msi_usable_sites,
        "TMB % Exon 50X": tmb_pct_exon_50X,
    }
    tmb_msi_metric_info.append(tmb_msi_variant_info)

    return tmb_msi_metric_info


def extract_data_from_report_json(report_json):
    """
    Parse JSON data and return a list of dictionaries.

    Parameters
    ----------
    report_json : JSON object
        The JSON object containing information from the report API results.

    Returns
    -------
    sample_id : str
        The sample ID for the report.
    case_info : dict
        A dictionary containing case specific information,
        i.e. analyst information.
    snvs_variants_info : list
        A list of dictionaries containing variant information for SNV.
    cnvs_variants_info : list
        A list of dictionaries containing variant information for CNV.
    indels_variants_info : list
        A list of dictionaries containing variant information for Indel.
    tmb_msi_metric_info : list
        A list of dictionaries containing variant information for TMB/MSI.
    """
    sample_id = report_json.get("displayId", "N/A")
    # Extract analyst information
    case_info = {
        "Primary Analyst": None,
        "First Checker": None,
        "Second Checker": None
    }

    for config_data in report_json.get("customMetadata", {}).get("configData", []):
        if config_data["name"] == "Primary analyst":
            case_info["Primary Analyst"] = config_data["value"]
        elif config_data["name"] == "First Checker":
            case_info["First Checker"] = config_data["value"]
        elif config_data["name"] == "Second checker":
            case_info["Second Checker"] = config_data["value"]

    # Extract variant information
    snvs_variants_info = []
    cnvs_variants_info = []
    indels_variants_info = []
    tmb_msi_metric_info = []

    # Extract variant and metric data
    # SNVs
    snvs_variants_info = extract_SNV_data(report_json)
    # CNVs and indels
    cnvs_variants_info, indels_variants_info = extract_CNV_indels_data(report_json)
    # extract MSI and TMB metrics, should these always be present?
    tmb_msi_metric_info = extract_TMB_MSI_data(report_json)

    # Print extracted information - TODO: rm for deployement
    print("Analyst Information:")
    for key, value in case_info.items():
        print(f"{key}: {value}")

    print("\nVariant Information:")
    for variant in snvs_variants_info:
        print(variant)
    for variant in cnvs_variants_info:
        print(variant)
    for variant in indels_variants_info:
        print(variant)
    for variant in tmb_msi_metric_info:
        print(variant)

    return sample_id, case_info, snvs_variants_info, \
        cnvs_variants_info, indels_variants_info, tmb_msi_metric_info


def json_extract_to_excel(sample_id, case_info,
                          snvs_variants_info, cnvs_variants_info,
                          indels_variants_info, tmb_msi_metric_info
                          ):
    """
    Extract information from a JSON file and write to an Excel file

    Parameters
    ----------
    sample_id : str
        The sample ID for the report.
    case_info : dict
        A dictionary containing analyst information.
    snvs_variants_info : list
        A list of dictionaries containing variant information
        for SNV.
    cnvs_variants_info : list
        A list of dictionaries containing variant information
        for CNV.
    indels_variants_info : list
        A list of dictionaries containing variant information
        for Indel.
    tmb_msi_metric_info : list
        A list of dictionaries containing metric information
        for TMB/MSI.

    Outputs
    -------
    Excel File
        Generates an Excel file with the extracted information.

    Returns
    -------
    None

    Raises
    ------
    None

    Examples
    --------
    >>> json_extract_to_excel("sample_id", case_info,
                              snvs_variants_info, cnvs_variants_info,
                              indels_variants_info, tmb_msi_metric_info
                             )

    """
    # Create a Pandas DataFrame from the extracted information
    case_info_df = pd.DataFrame([case_info])
    snvs_variants_info_df = pd.DataFrame(snvs_variants_info)
    cnvs_variants_info_df = pd.DataFrame(cnvs_variants_info)
    indels_variants_info_df = pd.DataFrame(indels_variants_info)
    small_variants_df = pd.concat(
        [snvs_variants_info_df, indels_variants_info_df], ignore_index=True)
    # Add an empty 'Tier' column to variant tables
    small_variants_df['Tier'] = ''
    cnvs_variants_info_df['Tier'] = ''
    tmb_msi_metric_info_df = pd.DataFrame(tmb_msi_metric_info)
    # Write the extracted information to an Excel file
    with pd.ExcelWriter(f"{sample_id}_extracted_information.xlsx", engine='xlsxwriter') as writer:
        single_sheet_name = "Reported_Variants_and_Metrics"
        workbook = writer.book
        worksheet = workbook.add_worksheet(single_sheet_name)
        writer.sheets[single_sheet_name] = worksheet
        row_pos = 0

        # Helper function to write a section header and DataFrame
        def write_section(df, header):
            nonlocal row_pos
            workbook = writer.book
            worksheet = writer.sheets[single_sheet_name]
            merge_format = workbook.add_format(
                {'bold': True, 'align': 'center', 'valign': 'vcenter'}
                )
            # Set column widths
            for i, col in enumerate(df.columns):
                max_len = max(df[col].astype(str).map(len).max(), len(col)) + 2
                worksheet.set_column(i, i, max_len)
            num_cols = len(df.columns) if not df.empty else 8
            worksheet.merge_range(row_pos, 0, row_pos,
                      num_cols - 1, header, merge_format)
            row_pos += 1

            if df.empty:
                worksheet.merge_range(
                    row_pos, 0, row_pos, num_cols - 1, "No variants reported", merge_format)
                row_pos += 2
            else:
                df.to_excel(writer, sheet_name=single_sheet_name,
                        startrow=row_pos, startcol=0, index=False)
                row_pos += len(df) + 2

        write_section(small_variants_df, "Small_Variants")
        write_section(cnvs_variants_info_df, "CNVs")
        write_section(tmb_msi_metric_info_df, "TMB_MSI")
        write_section(case_info_df, "Analyst Information")


# To deploy, we need to implement the following functions:
# def move_reports_to_clingen(destination_dir):
#     """
#     Move reports to the ClinGen folder in the ICI API.

#     Parameters
#     ----------
#     destination_dir: str
#         The destination directory to move the reports.

#     Returns
#     -------
#     None
#     """
#     # Move excel files in directory to ClinGen folder
#     destination_dir = "/old_reports"
#     os.makedirs(destination_dir, exist_ok=True)

#     for f in os.listdir("."):
#         if f.endswith(".xlsx"):
#             dest_path = os.path.join(destination_dir, f)
#             if os.path.exists(dest_path):
#                 logging.warning(f"File already exists in the new directory: {dest_path}")
#             else:
#                 shutil.move(f, dest_path)

def main():
    """
    Main function to initialize constants and execute the script.
    Returns
    -------
    None
    """

    # Get environment variables
    dotenv.load_dotenv()
    base_url = os.getenv("ICI_BASE_URL")
    api_key = os.getenv("ICI_API_KEY")
    audit_log_endpoint = os.getenv("ICI_AUDIT_LOG_ENDPOINT")
    case_status_updated_event = os.getenv("ICI_CASE_STATUS_UPDATED_EVENT")
    x_illumina_workgroup = os.getenv("X_ILMN_WORKGROUP")
    report_pattern = os.getenv("STATUS_STRING")
    report_pattern = rf'{report_pattern}'
    api_page_size = os.getenv("API_PAGE_SIZE")
    script_start_time_file = os.getenv("SCRIPT_START_TIME_FILE")

    args = parse_args()
    if args.mode == 'manual':
        args = parse_args()
        created_before = args.created_before
        created_after = args.created_after
    elif args.mode == 'cron':
        previous_start_time, current_start_time = log_start_time(
            script_start_time_file
        )
        created_before = current_start_time
        created_after = previous_start_time
    else:
        raise ValueError("Invalid mode. Please use 'manual or 'cron'.")

    # Setup API headers
    headers = setup_api(api_key, x_illumina_workgroup)
    # Execute script
    logging.info("Script execution started.")
    audit_logs = get_audit_logs(base_url, headers,
                                case_status_updated_event,
                                audit_log_endpoint,
                                created_after=created_after,
                                created_before=created_before,
                                page_size=api_page_size
                                )
    if audit_logs:
        logging.info("Audit logs fetched successfully.")
        process_reports_and_generate_excel(
            audit_logs, base_url, headers, report_pattern)
    else:
        logging.warning("No relevant audit logs found.")
    logging.info("Script execution completed.")


if __name__ == "__main__":
    main()
