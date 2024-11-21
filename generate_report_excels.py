import argparse
import requests
import re
import pandas as pd
import logging
import dotenv
import os

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
    parser = argparse.ArgumentParser(description='Process some integers.')
    parser.add_argument('--created_before', type=str, default=None,
                        help='The date string in the format YYYY-MM-DD\'T\'HH:MM:SS\'Z\''
                        'e.g: 2024-01-01T08:30:00Z to filter reports created before this date.')
    parser.add_argument('--created_after', type=str, default=None,
                        help='The date string in the format YYYY-MM-DD\'T\'HH:MM:SS\'Z\''
                        'e.g: 2024-01-01T08:30:00Z to filter reports created after this date.')
    parser.add_argument('--override_report_pattern', type=str, default='REPORTS_SIGNED_OFF',
                        help='The regex pattern to match in the report text.')
    args = parser.parse_args()
    return args


def setup_api(base_url, api_key, x_illumina_workgroup):
    """
    Setup the API headers for the request.

    Parameters
    ----------
    base_url : str
        The base URL for the ICI API.
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
                   created_before=None, created_after=None):
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

    Returns
    -------
    list
        A list of audit log entries, each represented as a dictionary. If an error occurs, returns an empty list.

    Examples
    --------
    >>> logs = get_audit_logs("https://api.ici.example.com", headers, "case.status.updated", "als/api/v1/auditlogs/search")
    """
    logging.info("Fetching audit logs from ICI API.")
    url = f"{base_url}{endpoint}"
    params = {
        "eventName": event_name,
        "toDate": created_before,
        "fromDate": created_after,
        "pageNumber": 0,
        "pageSize": 1000  # Adjust page size as needed
    }

    try:
        response = requests.get(url, headers=headers, params=params)
        logging.debug("Audit logs response: %s", response.json())
        return response.json().get("content", [])
    except requests.exceptions.RequestException as e:
        logging.error("Error fetching audit logs: %s", e)
        return []


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
        A list of audit log entries, each represented as a dictionary. The logs are filtered and matched
        to fetch corresponding reports.
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
    >>> logs = get_audit_logs("https://api.ici.example.com", headers, "case.status.updated")
    >>> process_reports_and_generate_excel(logs, "https://api.ici.example.com", headers, "your_regex_pattern_here")
    """
    logging.info("Processing audit logs and fetching reports.")
    matched_reports = []

    for log in audit_logs:
        case_id = log.get("caseId")
        print(case_id)
        # Assuming report text is in the 'message' field
        report_text = log.get("message", "")

        if re.search(report_pattern, report_text):
            logging.debug(
                "Report text matched pattern for case ID: %s", case_id)
            report_json = get_report(base_url, headers, case_id)
            if report_json:
                matched_reports.append(report_json)
        else:
            logging.debug("No match for case ID: %s", case_id)

    if matched_reports:
        logging.info("Generating Excel file from matched reports.")
        for report in matched_reports:
            sample_id, analyst_info, snvs_variants_info, cnvs_variants_info, indels_variants_info, tmb_msi_variants_info = parse_json(
                report)
            json_extract_to_excel(
                sample_id, analyst_info, snvs_variants_info,
                cnvs_variants_info, indels_variants_info,
                tmb_msi_variants_info
            )
    else:
        logging.warning("No matched reports found to generate Excel.")


def parse_json(report_json):
    """
    Parse JSON data and return a list of dictionaries.

    Parameters
    ----------
    report_json : JSON object
        The JSON data to be parsed.

    Returns
    -------
    sample_id : str
        The sample ID for the report.
    analyst_info : dict
        A dictionary containing analyst information.
    snvs_variants_info : list
        A list of dictionaries containing variant information for SNV.
    cnvs_variants_info : list
        A list of dictionaries containing variant information for CNV.
    indels_variants_info : list
        A list of dictionaries containing variant information for Indel.
    tmb_msi_variants_info : list
        A list of dictionaries containing variant information for TMB/MSI.
    """
    sample_id = report_json.get("displayId", "N/A")
    # Extract analyst information
    analyst_info = {
        "Primary Analyst": None,
        "First Checker": None,
        "Second Checker": None
    }
    for config_data in report_json.get("customMetadata", {}).get("configData", []):
        if config_data["name"] == "Primary analyst":
            analyst_info["Primary Analyst"] = config_data["value"]
        elif config_data["name"] == "First Checker":
            analyst_info["First Checker"] = config_data["value"]
        elif config_data["name"] == "Second checker":
            analyst_info["Second Checker"] = config_data["value"]

    # Extract variant information
    snvs_variants_info = []
    cnvs_variants_info = []
    indels_variants_info = []
    tmb_msi_variants_info = []
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
            vaf = finding.get("sampleMetrics", {}).get("alleleDepth", "N/A")
            if vaf != "N/A" and isinstance(vaf, (int, float)):
                try:
                    vaf = round(vaf / finding.get("sampleMetrics",
                                {}).get("totalDepth", 1), 3)
                except TypeError as e:
                    print("Error: VAF calculation issue. See Error: %s", e)
            fold_change = "N/A"
            pathogenicity = ", ".join(
                [a.get("actionabilityName", "N/A") for a in finding.get("actionabilities", [])])
            metric, metric_score, metric_status = "N/A", "N/A", "N/A"
            variant_info = {
                "Gene": gene,
                "Consequence": consequence,
                "Transcript": transcript,
                "DNA Nomenclature": dna_nomenclature,
                "Protein": protein,
                "VAF": vaf,
                "Pathogenicity": pathogenicity,
            }
            snvs_variants_info.append(variant_info)

        # extract variant information for CNV
        elif variant_type == "CNV":
            fold_change = next((m.get("value").split(": ")[1] for m in finding.get(
                "metrics", []) if "Fold change" in m.get("value", "")), "N/A")
            gene = finding.get("name", "N/A")
            transcript = "Unavailable"
            pathogenicity = ", ".join(
                [a.get("actionabilityName", "N/A") for a in finding.get("actionabilities", [])])
            variant_info = {
                "Gene": gene,
                "fold_change": fold_change,
                "Transcript": transcript,
                "Pathogenicity": pathogenicity,
            }
            cnvs_variants_info.append(variant_info)
        elif variant_type == "Indel":
            print("Indel")
            exit()
        elif variant_type == "TMB/MSI":
            gene, consequence, transcript, dna_nomenclature, protein, vaf = \
                "N/A", "N/A", "N/A", "N/A", "N/A", "N/A"
            metric = finding.get("name", "N/A")
            metric_score = finding.get("value", "N/A")
            metric_status = finding.get("scoreStatus", "N/A")
            variant_info = {
                "metric": metric,
                "metric_score": metric_score,
                "metric_status": metric_status,
            }
        else:
            print("Unknown variant type")
            print(variant_type)
            print(finding)
            exit()

    # Print or return the extracted information
    print("Analyst Information:")
    for key, value in analyst_info.items():
        print(f"{key}: {value}")

    print("\nVariant Information:")
    for variant in snvs_variants_info:
        print(variant)
    for variant in cnvs_variants_info:
        print(variant)
    for variant in indels_variants_info:
        print(variant)
    for variant in tmb_msi_variants_info:
        print(variant)

    return sample_id, analyst_info, snvs_variants_info, \
        cnvs_variants_info, indels_variants_info, tmb_msi_variants_info


def json_extract_to_excel(sample_id, analyst_info,
                          snvs_variants_info, cnvs_variants_info,
                          indels_variants_info, tmb_msi_variants_info
                          ):
    """
    Extract information from a JSON file and write to an Excel file

    Parameters
    ----------
    sample_id : str
        The sample ID for the report.
    analyst_info : dict
        A dictionary containing analyst information.
    variants_info : list
        A list of dictionaries containing variant information
        for SNV, CNV, or Indel.
    """
    # Create a Pandas DataFrame from the extracted information
    analyst_info_df = pd.DataFrame([analyst_info])
    snvs_variants_info_df = pd.DataFrame(snvs_variants_info)
    cnvs_variants_info_df = pd.DataFrame(cnvs_variants_info)
    indels_variants_info_df = pd.DataFrame(indels_variants_info)
    tmb_msi_variants_info_df = pd.DataFrame(tmb_msi_variants_info)
    # Write the extracted information to an Excel file
    with pd.ExcelWriter(f"{sample_id}_extracted_information.xlsx") as writer:
        snvs_variants_info_df.to_excel(
            writer, sheet_name="SNVs", index=False)
        cnvs_variants_info_df.to_excel(
            writer, sheet_name="CNVs", index=False)
        indels_variants_info_df.to_excel(
            writer, sheet_name="Indels", index=False)
        tmb_msi_variants_info_df.to_excel(
            writer, sheet_name="TMB_MSI", index=False)
        analyst_info_df.to_excel(
            writer, sheet_name="Analyst Information", index=False)


def main():
    """
    Main function to initialize constants and execute the script.

    Returns
    -------
    None
    """
    args = parse_args()
    # Constants, TODO: put this in a function and return the values
    # read in API key from a file or environment variable
    dotenv.load_dotenv()
    base_url = os.getenv("ICI_BASE_URL")
    api_key = os.getenv("ICI_API_KEY")
    audit_log_endpoint = os.getenv("ICI_AUDIT_LOG_ENDPOINT")

    # Example event name for case status updates
    case_status_updated_event = os.getenv("ICI_CASE_STATUS_UPDATED_EVENT")
    x_illumina_workgroup = os.getenv("X_ILMN_WORKGROUP")

    # The pattern to match in the report text
    report_pattern = os.getenv("STATUS_STRING")
    report_pattern = rf'{report_pattern}'
    # Testing pattern
    report_pattern = r'^Created report for case ID'  # r'\bREPORTS_SIGNED_OFF\b'
    if args.override_report_pattern:
        report_pattern = args.override_report_pattern
    # Setup API headers
    headers = setup_api(base_url, api_key, x_illumina_workgroup)

    # Execute script
    logging.info("Script execution started.")
    audit_logs = get_audit_logs(base_url, headers,
                                case_status_updated_event,
                                audit_log_endpoint,
                                created_after=args.created_after,
                                created_before=args.created_before
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
