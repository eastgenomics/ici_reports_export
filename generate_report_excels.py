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
import sys
import datetime as dt

# Third-party imports
import argparse
import dotenv
import pandas as pd
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from requests.exceptions import RequestException
from functools import reduce

# Local imports
from utils.notify_slack import SlackClient


class ErrorCollectorHandler(logging.Handler):
    def __init__(self):
        super().__init__(level=logging.ERROR)
        self.error_logs = []  # Store error messages here

    def emit(self, record):
        log_entry = self.format(record)
        self.error_logs.append(log_entry)


def setup_logging(stream_level=logging.INFO, error_file='errors.log'):
    """
    Setup logging for the script. Two outputs sys.stdout and ici_reports.log.
    sys.stdout is for Docker logs and ici_reports.log is for collated error logs.

    Parameters
    ----------
    stream_level : int
        The logging level for the stream handler.
    error_file : str
        The file name to store the error logs.

    Returns
    -------
    logger: logging.Logger
    """
    global logger
    global error_collector
    # Create a root logger and set its level
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    if logger.hasHandlers():
        logger.handlers.clear()
    # Stream handler for stdout (Docker logs)
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setLevel(stream_level)
    stream_formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s')
    stream_handler.setFormatter(stream_formatter)

    # File handler for errors (collated error log)
    error_handler = logging.FileHandler('ici_reports.log')
    # Only log errors and above to the file
    error_handler.setLevel(logging.ERROR)
    error_formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s')
    error_handler.setFormatter(error_formatter)

    # Custom error collector handler
    error_collector = ErrorCollectorHandler()
    error_collector.setFormatter(stream_formatter)

    # Add both handlers to the logger
    logger.addHandler(stream_handler)
    logger.addHandler(error_handler)
    logger.addHandler(error_collector)

    return logger, error_collector

# Function to retrieve all collected errors


def get_collected_errors():
    return error_collector.error_logs


def send_outcome_notification():
    """
    Send a notification to Slack with the collected errors.

    Parameters
    ----------
    None

    Returns
    -------
    None

    Outputs
    -------
    Slack message
        Sends a message to the specified Slack channel with the collected errors.
    """
    errors = get_collected_errors()
    variant_errors = []
    case_errors = []
    runtime_errors = []
    other_errors = []

    # Sort errors into categories
    for error in errors:
        if "Unknown variant type" in error:
            variant_errors.append(error)
        elif "Case" in error:
            case_errors.append(error)
        elif "Runtime Error" in error:
            runtime_errors.append(error)
        else:
            other_errors.append(error)

    if errors:
        notification_parts = []
        if runtime_errors:
            notification_parts.append(":gear: **Runtime Errors:**")
            for err in runtime_errors:
                err_part = err.split("ERROR")[1].strip(
                    " -") if "ERROR" in err else err
                notification_parts.append(err_part)

        if case_errors:
            notification_parts.append(":x: **Case Errors:**")
            for err in case_errors:
                err_part = err.split("ERROR")[1].strip(
                    " -") if "ERROR" in err else err
                notification_parts.append(err_part)

        if variant_errors:
            notification_parts.append(":x: **Variant Errors:**")
            for err in variant_errors:
                err_part = err.split("ERROR")[1].strip(
                    " -") if "ERROR" in err else err
                notification_parts.append(err_part)

        if other_errors:
            notification_parts.append(":exclamation: **Other Errors:**")
            for err in other_errors:
                err_part = err.split("ERROR")[1].strip(
                    " -") if "ERROR" in err else err
                notification_parts.append(err_part)

        notification = "\n".join(notification_parts)
        print("\n--- Sending Error Notification ---")
        slack_client = SlackClient()
        slack_client.post_message(message=notification, channel="alerts")
    else:
        slack_client = SlackClient()
        slack_client.post_message(
            message="Ici-report-export script ran successfully.", channel="log")
        print("No errors to notify.")


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
    parser.add_argument('--created_before', type=str, default=None,
                        help='The date string in the format YYYY-MM-DD\'T\'HH:MM:SS\'Z\''
                        'e.g: 2024-01-01T08:30:00Z to filter reports created before this date.'
                        'This overrides the start time file which records the previous runtime.')
    parser.add_argument('--created_after', type=str, default=None,
                        help='The date string in the format YYYY-MM-DD\'T\'HH:MM:SS\'Z\''
                        'e.g: 2024-01-01T08:30:00Z to filter reports created after this date.')
    args = parser.parse_args()

    # Validate inputs
    created_before_dt_obj = validate_date(
        args.created_before, "created_before"
        )
    created_after_dt_obj = validate_date(
        args.created_after, "created_after"
        )


    if created_after_dt_obj is not None and created_before_dt_obj is not None:
        epoch_seconds_before = int(created_before_dt_obj.timestamp())
        epoch_seconds_after = int(created_after_dt_obj.timestamp())
        if epoch_seconds_before < epoch_seconds_after:
            logger.error("Invalid date range: created_before < created_after")
            raise ValueError("Invalid date range: created_before < created_after")
        logger.info(
            "Date range: created_after = %s, created_before = %s",
            created_after_dt_obj, created_before_dt_obj
        )
        return args
    if created_after_dt_obj is not None or created_before_dt_obj is not None:
        logger.info(
            "Single date provided. Fetching reports for that date range."
        )
        return args
    elif created_after_dt_obj is None and created_before_dt_obj is None:
        logger.info("No date range provided.")
        return args
    else:
        logger.error("Invalid date range: created_after or created_before is None")
        raise RuntimeError("Invalid date range: created_after or created_before is None")



def validate_date(date_str, param_name):
    """Validate date string format."""
    if date_str is None:
        return
    try:
        sanatized_dt_obj = dt.datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%SZ")
        return sanatized_dt_obj
    except ValueError as e:
        logger.error(f"Invalid date format for {param_name}: {date_str}. See Error: {e}")
        raise ValueError(
            f"Invalid date format for {param_name}: {date_str}. See Error: {e}"
        ) from e


def log_start_time(start_time_file, args):
    """
    Log the start time of the script execution and store it in a file.

    Parameters
    ----------
    start_time_file : str
        The file name to store the start time.
    args: argparse.Namespace
        The arguments from the command line.

    Returns
    -------
    tuple
        A tuple containing the previous start time and the current start time.
    """
    current_start_time = dt.datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")

    # Read the previous start time from the file
    if os.path.exists(start_time_file):
        with open(start_time_file, 'r') as file:
            previous_start_time = file.read().strip()
    else:
        logger.info("No previous start time found in the log file.")
        logger.info(f"Script start time recorded: {current_start_time}")
        if args.created_before or args.created_after:
            logger.info(
                "Arguments provided."
                "Therefore no need to write the current start time to the file."
            )
            return None, current_start_time
        logger.info("Writing the current start time to the file.")
        with open(start_time_file, 'w') as file:
            file.write(current_start_time)
        # Continue running as other args may be provided
        return None, current_start_time

    # Validate the previous start time
    try:
        previous_start_time = dt.datetime.strptime(
            previous_start_time, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        logger.warning(
            "Invalid previous start time format in the log file.")
        previous_start_time = None

    # Write the current start time to the file
    with open(start_time_file, 'w') as file:
        file.write(current_start_time)

    logger.info("Script start time recorded: %s", current_start_time)
    return previous_start_time, current_start_time


def setup_api_headers(api_key, x_illumina_workgroup):
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
    logger.info("Fetching audit logs from ICI API.")
    url = f"{base_url}{endpoint}"
    params = {
        "eventName": event_name,
        "toDate": created_before,
        "fromDate": created_after,
        "pageNumber": 0,
        "pageSize": page_size
    }

    try:
        session = requests.Session()
        retry = Retry(
            total=5,
            backoff_factor=10,
            status_forcelist=[429, 500, 502, 503, 504]
        )
        adapter = HTTPAdapter(max_retries=retry)
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        response = session.get(url, headers=headers, params=params)
        response.raise_for_status()
        if response.status_code == 200:
            logger.debug(f"Audit logs response: {response.json()}")
            return response.json().get("content", [])
        else:
            logger.error(
                f"Runtime Error fetching audit logs: {response.status_code}")
            raise RequestException(
                f"Error fetching audit logs. Status code: {response.status_code}"
            )
    except RequestException as e:
        logger.error(
            f"Runtime Error, request exception while fetching audit logs: {e}")
        raise RequestException(
            f"Error fetching audit logs. {e}"
        ) from e


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
    logger.info("Fetching report for case ID: %s", case_id)
    url = f"{base_url}drs/v1/draftreport/case/{case_id}/reportjson"

    try:
        session = requests.Session()
        retry = Retry(
            total=3,
            backoff_factor=2,
            status_forcelist=[429, 500, 502, 503, 504]
        )
        adapter = HTTPAdapter(max_retries=retry)
        session.mount('http://', adapter)
        session.mount('https://', adapter)

        response = session.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except RequestException as e:
        logger.error(f"Case Error ({case_id}): error fetching report, {e}")
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
    logger.info("Processing audit logs and fetching reports.")
    matched_reports = []

    for log in audit_logs:
        case_id = log.get("caseId")
        ici_id = log.get("id")
        # Assuming report text is in the 'message' field
        report_text = log.get("message", "")
        if re.search(report_pattern, report_text, re.IGNORECASE):
            logger.info(
                "Report text matched pattern for case ID: %s", case_id)
            report_json = get_report(base_url, headers, case_id)
            if report_json:
                matched_reports.append(report_json)
        else:
            logger.error(
                f"Case Error ({case_id}): No match for case ID. ICI id = {ici_id}")
            logger.info(f"Report text: {report_text}")
            logger.info(f"Pattern: {report_pattern}")

    if matched_reports:
        logger.info("Generating Excel file from matched reports.")
        # Audits can be duplicated, so we need to filter out duplicates
        # for odd cases when they are regenerated in the same time-period
        # only keep the latest report
        unique_by_id = {}
        for rpt in matched_reports:
            rid = rpt.get("id")
            if rid not in unique_by_id or rpt.get("updatedDate", "") > unique_by_id[rid].get("updatedDate", ""):
                # Additional check for matching displayId
                if rid in unique_by_id and unique_by_id[rid].get("displayId") != rpt.get("displayId"):
                    logger.warning("Mismatch in displayId for the same ID")
                unique_by_id[rid] = rpt

        matched_reports = list(unique_by_id.values())

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
        logger.warning("No matched reports found to generate Excel.")

    return matched_reports


def select_association_consequences(associations):
    """
    Extract association consequences from the report JSON.
    Parameters
    ----------
    associations : list
        A list of dictionaries containing association information.
    Returns
    -------
    consequences : str
        A string containing the consequences of the association.
    """
    consequence_labels = []
    consequences_list = []
    # consequences from association
    associations_list = [
        assoc.get("associationInfo", {}
                  ).get("biomarkers", []) for assoc in associations
    ]

    biomarkers_list = reduce(lambda x, y: x + y, associations_list, [])

    for biomarker in biomarkers_list:
        consequences_list.append(biomarker.get("consequences", []))

    consequences_list = reduce(lambda x, y: x + y, consequences_list, [])

    for consequence in consequences_list:
        label = consequence.get("label", "")
        if label:
            consequence_labels.append(label)

    consequences = ", ".join(str(item) for item in consequence_labels)

    return consequences


def extract_variant_data(report_json):
    """
    Extract SNV, CNV and Indel data from the report JSON.

    Parameters
    ----------
    report_json : JSON object
        The JSON object containing information from the report API results.

    Returns
    -------
    snvs_variants_info : list
        A list of dictionaries containing variant information for SNV.
    cnvs_variants_info : list
        A list of dictionaries containing variant information for CNV.
    indels_variants_info : list
        A list of dictionaries containing variant information for Indel.
    """
    case_id = report_json.get("displayId", "N/A")
    cnvs_variants_info = []
    indels_variants_info = []
    # Different logic for extracting CNV information
    # Extract relevant section of the JSON for CNV information
    subject = report_json.get("subjects", [])
    if subject:
        reports_json = subject[0]
    else:
        logger.error(
            f"Case Error ({case_id}): No subjects found in the report. Truncated JSON.")

    reports = reports_json.get("reports")
    # Select only report
    if len(reports) > 1:
        logger.error(
            f"Case Error ({case_id}): Invalid number of reports found. Reports = {len(reports)}")
        raise RuntimeError(
            f"Invalid number of reports found. Reports = {len(reports)}")
    else:
        report = reports[0]
    # Extract CNV information
    variants = report.get("reportDetails", {}).get("variants", [])
    logger.info(f"No. Variants = {len(variants)}")
    # Extract CNV information
    snvs_variants_info = []
    cnvs_variants_info = []
    indels_variants_info = []

    for variant in variants:
        oncogenicity_list = []
        associations = []

        variant_type = variant.get("variantType", "Field not found")
        if variant_type is None:
            logger.error(
                f"Case Error ({case_id}): Variant type not found for variant."
                f"Variant JSON: {variant}"
            )

            continue
        elif variant_type == "SNV":
            gene = variant.get("gene", "N/A")
            transcript = variant.get("transcript", {}).get("name", "N/A")
            hgvsc = variant.get(
                "transcript", {}).get("hgvsc", "N/A")
            hgvsp = variant.get("transcript", {}).get("hgvsp", "N/A")
            if hgvsp is None:
                hgvsp = "p.?"
            vaf = variant.get("variantReadFrequency", None)
            try:
                if vaf is None:
                    logger.error(
                        f"Case Error ({case_id}): VAF not present for variant"
                    )
                    logger.info(f"Variant JSON: {variant}")
                elif isinstance(vaf, str):
                    vaf = float(vaf)
                vaf = round(vaf, 2)
            except (TypeError, ValueError) as e:
                logger.error(
                    f"Case Error ({case_id}): VAF calculation issue (SNV).  See Error: {e}")
            associations = variant.get("associations", [])
            oncogenicity_list = [
                assoc.get("actionabilityName", "N/A") for assoc in associations
            ]
            oncogenicity_list = set(oncogenicity_list)
            oncogenicity = ", ".join(oncogenicity_list)

            consequences = select_association_consequences(associations)

            variant_info = {
                "Gene": gene,
                "Consequences": consequences,
                "Transcript": transcript,
                "DNA": hgvsc,
                "Protein": hgvsp,
                "VAF": vaf,
                "Oncogenicity": oncogenicity,
            }
            snvs_variants_info.append(variant_info)
        elif re.search(r"Copy Number (Loss|Gain)", variant_type):
            fold_change = variant.get("foldChange", "N/A")

            if fold_change is None:
                logger.error(
                    f"Case Error ({case_id}): Fold change not present for variant"
                )

            gene = variant.get("gene", "N/A")

            transcript = variant.get("transcript", {}).get("name", "N/A")
            associations = variant.get("associations", [])

            # Get consequences from associations
            consequences = select_association_consequences(associations)

            oncogenicity_list = [
                assoc.get("actionabilityName", "N/A") for assoc in associations
            ]
            oncogenicity_list = set(oncogenicity_list)
            oncogenicity = ", ".join(oncogenicity_list)
            variant_info = {
                "Gene": gene,
                "Fold Change": fold_change,
                "Transcript": transcript,
                "Oncogenicity": oncogenicity,
                "Consequences": consequences,
            }
            cnvs_variants_info.append(variant_info)
        elif re.search(r"Insertion|Deletion|Delins|MNV", variant_type, re.IGNORECASE):
            gene = variant.get("gene", "N/A")
            transcript = variant.get("transcript", {}).get("name", "N/A")
            hgvsc = variant.get(
                "transcript", {}).get("hgvsc", "N/A")
            hgvsp = variant.get("transcript", {}).get("hgvsp", "N/A")
            if hgvsp is None:
                hgvsp = "p.?"
            vaf = variant.get("variantReadFrequency", None)
            try:
                if vaf is None:
                    logger.error(
                        f"Case Error ({case_id}): VAF not present for variant"
                    )
                    logger.info(f"Variant JSON: {variant}")
                elif isinstance(vaf, str):
                    vaf = float(vaf)
                vaf = round(vaf, 2)
            except TypeError as e:
                logger.error(
                    f"Case Error {case_id}: VAF calculation issue. See Error, {e}")

            associations = variant.get("associations", [])
            # Get consequences from associations
            consequences = select_association_consequences(associations)
            # Get oncogenicity from associations
            oncogenicity_list = [
                assoc.get("actionabilityName", "N/A") for assoc in associations
            ]
            oncogenicity_list = set(oncogenicity_list)
            oncogenicity = ", ".join(oncogenicity_list)

            variant_info = {
                "Gene": gene,
                "Consequences": consequences,
                "Transcript": transcript,
                "DNA": hgvsc,
                "Protein": hgvsp,
                "VAF": vaf,
                "Oncogenicity": oncogenicity,
            }
            indels_variants_info.append(variant_info)
        else:
            logger.error(
                f"Case Error ({case_id}): Unknown variant type: {variant_type}")
            logger.info(f"Variant JSON: {variant}")

    return snvs_variants_info, cnvs_variants_info, indels_variants_info


def extract_TMB_MSI_data(report_json):
    """
    Extract TMB and MSI data from the report JSON.

    Parameters
    ----------
    report_json : JSON object
        The JSON object containing information from the report API results.

    Returns
    -------
    tmb_msi_metric_info : dict
        A list of dictionaries containing metric information for TMB/MSI.
    """

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

    tmb_msi_metric_info = {
        "TMB (mut/MB)": tmb_value,
        "MSI (% unstable sites) ": msi_value,
        "MSI Total Usable Sites": msi_usable_sites,
        "TMB % Exon 50X": tmb_pct_exon_50X,
    }

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
        "Analysed by": None,
        "Checked by": None,
        "M Code": None,
    }

    for config_data in report_json.get("customMetadata", {}).get("configData", []):
        if config_data["name"] == "Analysed by":
            case_info["Analysed by"] = config_data["value"]
        elif config_data["name"] == "Checked by":
            case_info["Checked by"] = config_data["value"]
        elif config_data["name"] == "M Code":
            case_info["M Code"] = config_data["value"]

    # Extract variant information
    snvs_variants_info = []
    cnvs_variants_info = []
    indels_variants_info = []
    tmb_msi_metric_info = []

    # Extract variant and metric data
    snvs_variants_info, cnvs_variants_info, indels_variants_info = extract_variant_data(
        report_json
    )
    # extract MSI and TMB metrics
    tmb_msi_metric_info = extract_TMB_MSI_data(report_json)

    # Print extracted information
    logger.info("Case Information:")
    for key, value in case_info.items():
        logger.info(f"{key}: {value}")

    logger.info("\nVariant Information:")
    for variant in snvs_variants_info:
        logger.info (variant)
    for variant in cnvs_variants_info:
        logger.info(variant)
    for variant in indels_variants_info:
        logger.info(variant)
    for variant in tmb_msi_metric_info:
        logger.info(variant)

    return sample_id, case_info, snvs_variants_info, \
        cnvs_variants_info, indels_variants_info, tmb_msi_metric_info


def colnum_to_excel_col(col_num):
    """Convert a zero-based column index to an Excel-style column letter."""
    col_str = ""
    while col_num >= 0:
        col_str = chr(col_num % 26 + ord('A')) + col_str
        col_num = col_num // 26 - 1
    return col_str


def write_section(writer, df, header, start_col=0, start_row=0):
    """
    Write a section to an Excel file.
    This creates a table with formatting containing metrics,
    variants or cass information.

    Parameters
    ----------
    writer : ExcelWriter
        The ExcelWriter object to write the section to.
    df : pandas.DataFrame
        The DataFrame containing the data to write.
    header : str
        The header for the section.
    start_col : int, optional
        The column to start writing in the excel, by default 0
    start_row : int, optional
        The row to start writing in the excel, by default 0

    Returns
    -------
    start_row: int
        The last row written to by this function.
        This is used to an input of where to start writing the next section.
    """
    worksheet = writer.sheets["Reported_Variants_and_Metrics"]
    workbook = writer.book

    arial_format = workbook.add_format(
        {'font_name': 'Arial', 'border': 1,
         'font_size': 10, 'align': 'center'}
    )
    merge_format = workbook.add_format(
        {'font_name': 'Arial', 'font_size': 10,
         'border': 2, 'bold': True, 'align': 'center',
         'valign': 'vcenter'}
    )
    header_format = workbook.add_format(
        {'font_name': 'Arial', 'border': 2,
         'font_size': 10, 'bold': True}
    )

    num_cols = len(df.columns) if not df.empty else 8
    worksheet.merge_range(start_row, start_col, start_row,
                          start_col + num_cols - 1, header, merge_format)
    start_row += 1

    if df.empty:
        worksheet.merge_range(
            start_row, start_col, start_row,
            start_col + num_cols - 1,
            "No variants reported", merge_format)
        start_row += 2
    else:
        # Write the headers
        for col_num, col_name in enumerate(df.columns):
            worksheet.write(start_row, start_col + col_num,
                            col_name, header_format)
        start_row += 1

        # Write the data row by row
        for r in range(len(df)):
            for c in range(len(df.columns)):
                col_name = df.columns[c]

                # Solution 1: Write the formula to the cell
                # with hard-coded value.

                # If this is the “Estimated copy number” column,
                # populate it with the “Fold Change” value for this row
                if col_name == "Estimated copy number" and "Fold Change" in df.columns:
                    fold_change_val = df.iloc[r][df.columns.get_loc(
                        "Fold Change")]
                    if fold_change_val is None or fold_change_val == "N/A":
                        formula = "N/A"
                    formula = f'=ROUND(((({fold_change_val}*200)-2*(100-$N$3))/$N$3), 2)'
                    worksheet.write(start_row + r, start_col +
                                    c, formula, arial_format)
                elif col_name == "Fold Change":
                    fold_change_val = df.iloc[r, c]
                    formula = f'=ROUND(({fold_change_val}), 2)'
                    worksheet.write(start_row + r, start_col +
                                    c, formula, arial_format)
                elif col_name == "TMB (mut/MB)":
                    value = df.iloc[r, c]
                    formula = f'=ROUND(({value}), 2)'
                    worksheet.write(start_row + r, start_col +
                                    c, formula, arial_format)
                else:
                    # Normal cell write
                    value = df.iloc[r, c]
                    worksheet.write(start_row + r, start_col +
                                    c, value, arial_format)

        start_row += len(df) + 2

    return start_row


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
    # Formatting
    # Desired columns order for CNVs
    desired_columns = [
        "Gene",
        "Consequence",
        "Transcript",
        "Estimated copy number",  # Will hold a formula
        "Tier",
        " ",  # Gap column
        "Fold Change",
    ]
    cnvs_variants_info_df = cnvs_variants_info_df.reindex(
        columns=desired_columns, fill_value="")
    # Assign a placeholder formula to the 'Estimated copy number' column
    cnvs_variants_info_df["Estimated copy number"] = "=SOME_EXCEL_FORMULA()"
    case_info_df["%TCC"] = ""  # Add an empty column for %TCC
    case_info_df["Sample_Id"] = sample_id

    # Add an empty 'Tier' column to variant tables
    small_variants_df['Tier'] = ''
    cnvs_variants_info_df['Tier'] = ''
    tmb_msi_metric_info_df = pd.DataFrame([tmb_msi_metric_info])
    # Write the extracted information to an Excel file
    with pd.ExcelWriter(f"{sample_id}_extracted_information.xlsx", engine='xlsxwriter') as writer:
        single_sheet_name = "Reported_Variants_and_Metrics"
        workbook = writer.book
        worksheet = workbook.add_worksheet(single_sheet_name)
        writer.sheets[single_sheet_name] = worksheet
        row_pos = 0

        # Increase the width for columns B and C (indices 1 and 2)
        worksheet.set_column(1, 1, 20)  # Column B
        worksheet.set_column(2, 2, 20)  # Column C
        row_pos = 0
        row_pos = write_section(writer, small_variants_df,
                                "Small Variants", start_col=0, start_row=row_pos)
        row_pos = write_section(
            writer, cnvs_variants_info_df, "CNVs", start_col=0, start_row=row_pos)
        row_pos = write_section(writer, tmb_msi_metric_info_df,
                                "TMB/MSI Metrics", start_col=0, start_row=row_pos)
        row_pos = 0  # Overwrite start position for next section
        row_pos = write_section(
            writer, case_info_df, "Case Information", start_col=10, start_row=row_pos)


def validate_env_vars():
    """Validate required environment variables."""
    required_vars = [
        "ICI_BASE_URL",
        "ICI_API_KEY",
        "ICI_AUDIT_LOG_ENDPOINT",
        "ICI_CASE_STATUS_UPDATED_EVENT",
        "X_ILMN_WORKGROUP",
        "STATUS_STRING",
        "API_PAGE_SIZE",
        "SCRIPT_START_TIME_FILE"
    ]
    missing_vars = [var for var in required_vars if not os.getenv(var)]
    if missing_vars:
        logger.error(
            f"Runtime Error: Missing required environment variables: {', '.join(missing_vars)}")
        raise RuntimeError("Missing environment variables. See logs.")


def check_failed_audit_logs(matched_reports, search_directory='/home/rswilson1/Documents/ici_reports_export'):
    """
    Check if all the reports are generated successfully.

    Parameters
    ----------
    matched_reports : list
        A list of reports from ICI, each represented as a dictionary.

    Returns
    -------
    matched_reports_count: int
        The number of reports that were successfully generated.
    """
    unique_by_display_id = {}
    for report in matched_reports:
        display_id = report.get("displayId")
        unique_by_display_id[display_id] = report

    matched_reports = list(unique_by_display_id.values())
    matched_reports_count = len(matched_reports)

    report_names = [report.get("displayId", "N/A")
                    for report in matched_reports]
    # Find all the reports that were not generated
    # Search for excels generated today
    today = dt.datetime.now().date()
    excel_files_generated_today = []

    for file_name in os.listdir(search_directory):
        if file_name.lower().endswith('.xlsx'):
            file_path = os.path.join(search_directory, file_name)
            if dt.datetime.fromtimestamp(os.path.getmtime(file_path)).date() == today:
                excel_files_generated_today.append(file_name)
    # Check if length of reports to be generared matched generated.
    if matched_reports_count != len(excel_files_generated_today):
        logger.error(
            f"Runtime Error: Reports to be generated: {matched_reports_count}")
        logger.error(
            f"Runtime Error: Excel files generated today: {excel_files_generated_today}")
        logger.error("Runtime Error: Incorrect number of reports present.")
    else:
        logger.info("Correct number of reports generated.")
        logger.info(
            f"Excel files generated today: {excel_files_generated_today}")
        slack_client = SlackClient()
        slack_client.post_message(
            message="Correct number of reports generated.", channel="log")

    return matched_reports_count, report_names


def main():
    """
    Main function to initialize constants and execute the script.
    Returns
    -------
    None
    """
    logger, error_collector = setup_logging()
    # Get environment variables
    dotenv.load_dotenv()
    validate_env_vars()
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
    previous_start_time, current_start_time = log_start_time(
        script_start_time_file,
        args
    )

    # Check if the user has provided a start time
    if args.created_before:
        created_before = args.created_before
    else:
        created_before = None
    if args.created_after:
        created_after = args.created_after
    else:
        created_after = None
    if not args.created_before and not args.created_after:
        # No set created_before and no set created_after times
        # Use the previous start time and current start time
        created_before = current_start_time
        created_after = previous_start_time

    # Setup API headers
    headers = setup_api_headers(api_key, x_illumina_workgroup)
    # Execute script
    logger.info("Script execution started.")
    audit_logs = get_audit_logs(base_url, headers,
                                case_status_updated_event,
                                audit_log_endpoint,
                                created_after=created_after,
                                created_before=created_before,
                                page_size=api_page_size
                                )

    if audit_logs:
        logger.info("Audit logs fetched successfully.")
        matched_reports = process_reports_and_generate_excel(
            audit_logs, base_url, headers, report_pattern
        )
        num_reports, report_names = check_failed_audit_logs(matched_reports)
        print(f"Number of reports generated: {num_reports}")
        # print report names individually
        print("Report names:")
        for report_name in report_names:
            print(report_name)
    else:
        logger.info("No relevant audit logs found.")

    # Trigger the notification
    send_outcome_notification()

    logger.info("Script execution completed.")


if __name__ == "__main__":
    main()
