""" Testing the generate_report_excels.py file """

import sys
import os
import json
from io import StringIO
from contextlib import contextmanager
import time

from unittest.mock import patch, Mock, mock_open, MagicMock
import unittest
from pytest import raises, mark, fixture
import re
import requests
from requests.exceptions import RequestException, HTTPError, ConnectionError, Timeout
import argparse
from dotenv import load_dotenv

# Add the parent directory to the path to import the module
sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..')))

from generate_report_excels import *
from utils.notify_slack import SlackClient

"""
Tests for the generate_report_excels.py file
"""
logger, error_collector = setup_logging()
load_dotenv()

@fixture
def mock_args():
    with patch('argparse.ArgumentParser.parse_args') as mock_parse_args:
        mock_parse_args.return_value = argparse.Namespace(
            created_before="2024-01-01T08:30:00Z",
            created_after="2023-01-01T08:30:00Z",
            override_report_pattern="test_pattern",
            single_report=False,
        )
        yield mock_parse_args


@fixture
def report_json():
    with open('tests/test_data/test_demo_breast.json') as f:
        data = json.load(f)
    yield data


class TestParseArguments():
    """
    Mocked testings for the argument parser
    """

    @mark.parametrize("created_before, created_after", [
        ("invalid_date", "2024-01-01T08:30:00Z"),
        ("invalid_date", "1900-02-01T08:30:00Z"),
        ("invalid_date", "0001-01-01T08:30:00Z"),
        ("invalid_date", "2300-01-03T08:30:00Z"),
        ("invalid_date", "2018-01-02T08:30:00Z"),
        ("invalid_date", "2024-12-01T08:30:00Z"),
        ("invalid_date", "2024-01-01T08:30:00Z"),
        ("invalid_date", "2024-01-02T08:30:00Z"),
        ("invalid_date", "2024-01-03T08:30:00Z"),
        ("invalid_date", "2024-01-04T08:30:00Z"),
        ("invalid_date", "2024-01-30T08:30:00Z"),
        ("invalid_date", "2024-01-12T08:30:00Z"),
    ])
    def test_invalid_date_format_created_before(self, mock_args, created_before, created_after):
        mock_args.return_value = argparse.Namespace(
            created_before=created_before,
            created_after=created_after,
        )
        with raises(ValueError):
            _args = parse_args()

    @mark.parametrize("created_before, created_after", [
        ("2024-01-01T08:30:00Z", "invalid_date"),
        ("2024-01-01T08:30:00Z", ""),
        ("2024-01-01T08:30:00Z", " "),
        ("2024-01-01T08:30:00Z", "2024-13-01T08:30:00Z"),
        ("2024-01-01T08:30:00Z", "2024-00-01T08:30:00Z"),
        ("2024-01-01T08:30:00Z", "2024-01-32T08:30:00Z"),
        ("2024-01-01T08:30:00Z", "2024-01-00T08:30:00Z"),
        ("2024-01-01T08:30:00Z", "2024-01-01T25:30:00Z"),
        ("2024-01-01T08:30:00Z", "2024-01-01T08:61:00Z"),
        ("2024-01-01T08:30:00Z", "2024-01-01T08:30:61Z"),
        ("2024-01-01T08:30:00Z", "2024-01-01T08:30:00"),
        ("2024-01-01T08:30:00Z", "2024-01-01T08:30"),
        ("2024-01-01T08:30:00Z", "2024-01-01")
    ])
    def test_invalid_date_format_created_after(self, mock_args, created_before, created_after):
        mock_args.return_value = argparse.Namespace(
            created_before=created_before,
            created_after=created_after,
        )
        if created_after == "":
            print("Empty string")
        with raises(ValueError):
            _args = parse_args()

    @mark.parametrize("created_before, created_after", [
        ("2024-01-01T08:31:00Z", "2024-01-01T08:30:00Z"),
        ("1900-02-01T08:30:00Z", "1899-02-01T08:30:00Z"),
        ("2024-01-01T08:30:00Z", "0002-01-01T08:30:00Z"),
        ("2300-02-03T08:30:00Z", "2300-01-03T08:30:00Z"),
        ("2018-01-04T08:30:00Z", "2018-01-02T08:30:00Z"),
        ("2024-12-01T10:30:00Z", "2024-12-01T08:30:00Z"),
        ("2024-01-01T08:30:01Z", "2024-01-01T08:30:00Z"),
        ("2024-01-02T08:30:10Z", "2024-01-02T08:30:00Z"),
        ("2024-01-05T08:30:00Z", "2024-01-03T08:30:00Z"),
        ("2024-01-04T13:30:00Z", "2024-01-04T08:30:00Z"),
        ("2024-01-30T23:30:00Z", "2024-01-30T08:30:00Z"),
        ("2024-11-12T08:30:00Z", "2024-01-12T08:30:00Z"),
    ])
    def test_valid_date_format_accepted(self, mock_args, created_before, created_after):
        with patch('argparse.ArgumentParser.parse_args') as mock_parse_args:
            mock_parse_args.return_value = argparse.Namespace(
                created_before=created_before,
                created_after=created_after,
                single_report=False,
            )
            args = parse_args()
            assert args.created_before == created_before
            assert args.created_after == created_after

    @mark.parametrize("created_before, created_after", [
        ("2023-01-01T08:30:00Z", "2024-01-01T08:30:00Z"),
        ("2023-01-01T08:30:00Z", "2024-02-01T08:30:00Z"),
        ("2024-01-01T08:30:00Z", "2024-01-02T08:30:00Z"),
        ("2023-01-01T08:30:00Z", "2023-01-01T08:30:01Z"),
        ("2024-01-01T08:30:00Z", "2024-01-01T09:30:00Z"),
        ("2023-01-01T08:30:00Z", "2023-01-01T08:50:00Z"),
    ])
    def test_if_created_before_and_after_when_swapped_raise_error(self, mock_args,
                                                                  created_before,
                                                                  created_after):
        with patch('argparse.ArgumentParser.parse_args') as mock_parse_args:
            mock_parse_args.return_value = argparse.Namespace(
                created_before=created_before,
                created_after=created_after,
                single_report=False,
            )
            with raises(ValueError):
                _args = parse_args()



@fixture
def return_test_demo_breast(report_json):
    # read in test data
    sample_id, case_info, snvs_variants_info, \
        cnvs_variants_info, indels_variants_info, tmb_msi_variants_info = (
            extract_data_from_report_json(report_json)
        )
    yield sample_id, case_info, snvs_variants_info, \
        cnvs_variants_info, indels_variants_info, tmb_msi_variants_info


class TestJsonParsing():
    """
    Check the parsing of the report JSONs returns correct data.
    """

    def test_CNVs_return_transcript(self, report_json, return_test_demo_breast):
        sample_id, case_info, snvs_variants_info, \
            cnvs_variants_info, indels_variants_info, \
            tmb_msi_variants_info = return_test_demo_breast

        # check if the CNVs return the correct transcript

        for variant in cnvs_variants_info:
            assert variant['Transcript'].startswith(("NM_", "ENST"))

    def test_CNVs_return_gene_symbol(self, report_json, return_test_demo_breast):
        sample_id, case_info, snvs_variants_info, \
            cnvs_variants_info, indels_variants_info, \
            tmb_msi_variants_info = return_test_demo_breast

        # check if the CNVs return a valid gene symbol
        for variant in cnvs_variants_info:
            assert re.match(r'^[A-Z][A-Z0-9]*$', variant['Gene'])

    def test_CNVs_return_oncogenicity(self, report_json, return_test_demo_breast):
        sample_id, case_info, snvs_variants_info, \
            cnvs_variants_info, indels_variants_info, \
            tmb_msi_variants_info = return_test_demo_breast
        print(cnvs_variants_info)
        # check if the CNVs return the correct transcript
        for variant in cnvs_variants_info:
            print(variant['Oncogenicity'])
            oncogenicity_list = variant['Oncogenicity'].split(', ')
            print(oncogenicity_list)
            list_accceptable_terms = ['Likely Pathogenic', 'Pathogenic',
                                      'Likely Oncogenic', 'Oncogenic']
            assert all(
                oncogenicity in list_accceptable_terms for oncogenicity in oncogenicity_list
            )


class TestLoggingTime():
    """
    Test the log_start_time function
    """
    @mark.parametrize("time_value", [
        "2023-01-01T08:30:00Z",
        "2023-02-01T08:30:01Z",
        "2023-03-01T08:30:02Z",
        "2023-01-02T08:30:03Z",
        "2023-01-03T08:30:04Z",
        "2023-01-10T08:30:05Z",
        "2023-01-10T09:30:05Z",
        "2023-01-10T10:30:05Z",
        "2023-01-10T10:45:05Z",
        "2022-01-01T08:30:00Z",
        "2023-01-01T08:30:00Z",
        "2024-01-01T08:30:00Z",
        "2025-01-01T08:30:00Z",
        "2030-01-01T08:30:00Z",
    ])
    def test_log_start_time(self, time_value):
        with patch('generate_report_excels.dt') as mock_dt:
            mock_dt.datetime.now.return_value.strftime.return_value = time_value
            mock_args = argparse.Namespace(
                created_before=None, created_after=None)
            prev_time, current_time = log_start_time(
                "tests/test_data/script_start_time.log",
                mock_args
            )
            assert current_time == time_value


class TestApiCalls():
    """
    Test the API calls to ICI with mock object.
    """
    # Mock data for API requests
    mock_url = "https://api.illumina.com/v1/"
    mock_headers = {
        'accept': '*/*',
        'Authorization': 'ApiKey API_KEY',
        'X-ILMN-Domain': 'domain_id',
        'X-ILMN-Workgroup': 'workgroup_id',
    }
    mock_event_name = "CaseCreated"
    mock_endpoint = "audit-logs"

    @mark.parametrize("error_code", [300, 404, 500])
    @patch("generate_report_excels.requests.Session")
    def test_non_200_errors(self, mock_session, error_code):
        mock_api = mock_session.return_value
        mock_api.get.return_value.status_code = error_code
        with raises(requests.exceptions.RequestException):
            _logs = get_audit_logs(self.mock_url,
                                   self.mock_headers,
                                   self.mock_event_name,
                                   self.mock_endpoint,
                                   "2023-01-01T08:30:00Z",
                                   "2024-01-01T08:30:00Z")

    def test_successful_https_code(self):
        with patch('generate_report_excels.requests.Session') as mock_session:
            mock_api = mock_session.return_value
            mock_api.get.return_value.status_code = 200
            mock_api.get.return_value.json.return_value = {
                "content": "test_content",
                "status": 200
            }
            output = get_audit_logs(self.mock_url,
                                    self.mock_headers,
                                    self.mock_event_name,
                                    self.mock_endpoint,
                                    "2023-01-01T08:30:00Z",
                                    "2024-01-01T08:30:00Z")
            assert mock_api.get.assert_called_once
            assert output == "test_content"

    @patch("generate_report_excels.requests.Session")
    def test_successful_https_code_empty_content(self, mock_session):
        mock_api = mock_session.return_value
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"content": []}
        mock_api.get.return_value = mock_response

        response = get_audit_logs(
            "https://api.ici.example.com/",
            {"Authorization": "Bearer token"},
            "case.report.added",
            "als/api/v1/auditlogs/search",
            "2024-01-01T08:30:00Z",
            "2023-01-01T08:30:00Z"
        )

        assert response == []
        mock_api.get.assert_called_once_with(
            "https://api.ici.example.com/als/api/v1/auditlogs/search",
            headers={"Authorization": "Bearer token"},
            params={
                "eventName": "case.report.added",
                "toDate": "2024-01-01T08:30:00Z",
                "fromDate": "2023-01-01T08:30:00Z",
                "pageNumber": 0,
                "pageSize": 1000
            }
        )

    @patch("generate_report_excels.requests.Session")
    def test_missing_keys_in_json_response(self, mock_session):
        """
        What is the expected behavior when the JSON response is missing keys?
        Response should be an empty list.
        Response should raise an error.
        """
        mock_api = mock_session.return_value
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {}
        mock_api.get.return_value = mock_response

        response = get_audit_logs(
            "https://api.ici.example.com/",
            {"Authorization": "Bearer token"},
            "case.report.added",
            "als/api/v1/auditlogs/search",
            "2024-01-01T08:30:00Z",
            "2023-01-01T08:30:00Z"
        )

        assert response == []
        mock_api.get.assert_called_once_with(
            "https://api.ici.example.com/als/api/v1/auditlogs/search",
            headers={"Authorization": "Bearer token"},
            params={
                "eventName": "case.report.added",
                "toDate": "2024-01-01T08:30:00Z",
                "fromDate": "2023-01-01T08:30:00Z",
                "pageNumber": 0,
                "pageSize": 1000
            }
        )


class TestSendOutcomeNotification(unittest.TestCase):

    @patch('utils.notify_slack.SlackClient.post_message')
    @patch('generate_report_excels.get_collected_errors')
    @patch('argparse.ArgumentParser.parse_args', return_value=argparse.Namespace(
        created_before=None, created_after=None, single_report=False, testing=True
    ))
    def test_no_errors(self, mock_parse_args, mock_get_collected_errors, mock_slack_post_message):
        mock_args = mock_parse_args.return_value
        print(mock_args)
        print(mock_args.testing)
        mock_get_collected_errors.return_value = []

        send_outcome_notification(mock_args)

        mock_slack_post_message.assert_called_once_with(message="No errors to notify. ICI report export script ran successfully.",
                                                        channel="log")

    @patch('utils.notify_slack.SlackClient.post_message')
    @patch('generate_report_excels.get_collected_errors')
    @patch('argparse.ArgumentParser.parse_args', return_value=argparse.Namespace(
        created_before=None, created_after=None, single_report=False, testing=False
    ))
    def test_runtime_errors(self, mock_parse_args, mock_get_collected_errors, mock_slack_post_message):
        mock_args = mock_parse_args.return_value
        mock_get_collected_errors.return_value = [
            "2025-02-07 13:53:42,140 - ERROR - Runtime Error: Some reports were not generated."
        ]
        expected_notification = ":gear: **Runtime Errors:**\nRuntime Error: Some reports were not generated."
        send_outcome_notification(mock_args)
        mock_slack_post_message.assert_called_once_with(message=expected_notification,
                                                        channel="alerts")

    @patch('generate_report_excels.get_collected_errors')
    @patch('utils.notify_slack.SlackClient.post_message')
    @patch('argparse.ArgumentParser.parse_args', return_value=argparse.Namespace(
        created_before=None, created_after=None, single_report=False, testing=False
    ))
    def test_case_errors(self, mock_parse_args, mock_slack_post_message, mock_get_collected_errors):
        mock_args = mock_parse_args.return_value
        mock_get_collected_errors.return_value = [
            "2025-02-07 13:53:42,140 - ERROR - Case ID 12345 not found"
        ]
        expected_notification = ":x: **Case Errors:**\nCase ID 12345 not found"
        send_outcome_notification(mock_args)
        mock_slack_post_message.assert_called_once_with(message=expected_notification,
                                                        channel="alerts")

    @patch('utils.notify_slack.SlackClient.post_message')
    @patch('generate_report_excels.get_collected_errors')
    @patch('argparse.ArgumentParser.parse_args', return_value=argparse.Namespace(
        created_before=None, created_after=None, single_report=False, testing=False
    ))
    def test_variant_errors(self, mock_parse_args, mock_get_collected_errors, mock_slack_post_message):
        mock_args = mock_parse_args.return_value
        mock_get_collected_errors.return_value = [
            "2025-02-07 13:53:42,140 - ERROR - Unknown variant type: XYZ"
        ]
        expected_notification = ":x: **Variant Errors:**\nUnknown variant type: XYZ"
        send_outcome_notification(mock_args)
        mock_slack_post_message.assert_called_once_with(message=expected_notification,
                                                        channel="alerts")


    @patch('utils.notify_slack.SlackClient.post_message')
    @patch('generate_report_excels.get_collected_errors')
    @patch('argparse.ArgumentParser.parse_args', return_value=argparse.Namespace(
        created_before=None, created_after=None, single_report=False, testing=False
    ))
    def test_other_errors(self, mock_parse_args, mock_get_collected_errors, mock_slack_post_message):
        mock_args = mock_parse_args.return_value
        mock_get_collected_errors.return_value = [
            "2025-02-07 13:53:42,140 - ERROR - Some other error occurred"
        ]
        expected_notification = ":exclamation: **Other Errors:**\nSome other error occurred"
        send_outcome_notification(mock_args)
        mock_slack_post_message.assert_called_once_with(message=expected_notification,
                                                        channel="alerts")


    @patch('utils.notify_slack.SlackClient.post_message')
    @patch('generate_report_excels.get_collected_errors')
    @patch('argparse.ArgumentParser.parse_args', return_value=argparse.Namespace(
        created_before=None,
        created_after=None,
        single_report=False,
        testing=False
    ))
    def test_runtime_errors_2(self, mock_parse_args, mock_get_collected_errors, mock_slack_post_message):
        mock_get_collected_errors.return_value = [
            "2025-02-07 13:53:42,140 - ERROR - Runtime Error: Some reports were not generated."
        ]
        mock_args = mock_parse_args.return_value

        expected_notification = (
            ":gear: **Runtime Errors:**\nRuntime Error: Some reports were not generated."
        )

        send_outcome_notification(mock_args)

        mock_slack_post_message.assert_called_once_with(
            message=expected_notification,
            channel="alerts"
        )

    @contextmanager
    def capture_stdout(self):
        old_stdout = sys.stdout
        sys.stdout = StringIO()
        try:
            yield sys.stdout
        finally:
            sys.stdout = old_stdout


class TestCheckFailedAuditLogs(unittest.TestCase):
    @patch('os.listdir')
    @patch('os.path.getmtime')
    @patch('utils.notify_slack.SlackClient.post_message')
    def test_no_matched_reports(self, mock_slack_post_message, mock_getmtime, mock_listdir):
        """Should return (0, []) when no matched reports are provided."""
        mock_listdir.return_value = []
        mock_getmtime.return_value = time.time()
        matched_reports = []
        matched_reports_count, report_names = check_failed_audit_logs(
            matched_reports)
        self.assertEqual(matched_reports_count, 0,
                         "Should return 0 for matched_reports_count.")
        self.assertEqual(report_names, [],
                         "Should return an empty list for report_names.")

    @patch('os.listdir')
    @patch('os.path.getmtime')
    @patch('utils.notify_slack.SlackClient.post_message')
    def test_single_report_file_found(self, mock_slack_post_message, mock_getmtime, mock_listdir):
        """Should return (1, ['CASE1234']) when a single matched report is provided and its file is found."""
        mock_listdir.return_value = ['CASE1234.xlsx']
        mock_getmtime.return_value = time.time()
        matched_reports = [{'displayId': 'CASE1234'}]
        matched_reports_count, report_names = check_failed_audit_logs(
            matched_reports)
        self.assertEqual(matched_reports_count, 1,
                         "Should return 1 for matched_reports_count.")
        self.assertEqual(
            report_names, ['CASE1234'], "Should return ['CASE1234'] for report_names.")

    @patch('os.listdir')
    @patch('os.path.getmtime')
    @patch('utils.notify_slack.SlackClient.post_message')
    def test_single_report_file_not_found(self, mock_slack_post_message, mock_getmtime, mock_listdir):
        """
        Even if the Excel file doesn't match, the function still merges the
        matched reports and returns (1, ['CASE9999']) if there's 1 unique displayId.
        """
        mock_listdir.return_value = ['SOME_OTHER_FILE.xlsx']
        mock_getmtime.return_value = time.time()
        matched_reports = [{'displayId': 'CASE9999'}]
        matched_reports_count, report_names = check_failed_audit_logs(
            matched_reports)
        self.assertEqual(matched_reports_count, 1,
                         "Should still return 1 unique matched report.")
        self.assertEqual(report_names, ['CASE9999'])

    @patch('os.listdir')
    @patch('os.path.getmtime')
    @patch('utils.notify_slack.SlackClient.post_message')
    def test_duplicate_reports_merged(self, mock_slack_post_message, mock_getmtime, mock_listdir):
        """Should merge duplicates and return (1, ['CASE1234']) for the unique displayId."""
        mock_listdir.return_value = ['CASE1234.xlsx']
        mock_getmtime.return_value = time.time()
        matched_reports = [
            {'displayId': 'CASE1234', 'updatedDate': '2025-01-01T10:00:00Z'},
            {'displayId': 'CASE1234', 'updatedDate': '2025-01-02T12:00:00Z'},
        ]
        matched_reports_count, report_names = check_failed_audit_logs(
            matched_reports)
        self.assertEqual(matched_reports_count, 1,
                         "Should be 1 for unique displayId.")
        self.assertEqual(
            report_names, ['CASE1234'], "Should return ['CASE1234'] for report_names.")

    @patch('os.listdir')
    @patch('os.path.getmtime')
    # @patch('utils.notify_slack.SlackClient.post_message')
    @patch('generate_report_excels.SlackClient.post_message')
    def test_multiple_excel_files_found(self, mock_slack_post_message, mock_getmtime, mock_listdir):
        """
        Should log an error and notify if multiple Excel files are found for a single report.
        """
        mock_listdir.return_value = ['CASE1234.xlsx', 'CASE1234_duplicate.xlsx']
        mock_getmtime.return_value = time.time()
        matched_reports = [{'displayId': 'CASE1234'}]
        with self.assertLogs(logger, level='ERROR') as log:
            matched_reports_count, report_names = check_failed_audit_logs(
                matched_reports)
            self.assertIn("Runtime Error: Incorrect number of reports present.", log.output[-1])
        self.assertEqual(matched_reports_count, 1,
                         "Should still return 1 unique matched report despite duplicates.")
        self.assertEqual(report_names, ['CASE1234'])
        self.assertIn("Runtime Error: Incorrect number of reports present.", log.output[-1])

class TestColnumToExcelCol(unittest.TestCase):
    """
    Tests for the colnum_to_excel_col function that translates a zero-based
    integer index into an Excel-style column label.
    """

    def test_single_letter_A_to_Z(self):
        """
        Tests that column indices 0 through 25 translate correctly to letters A-Z.
        """
        self.assertEqual(colnum_to_excel_col(0), "A", "Column 0 should map to 'A'.")
        self.assertEqual(colnum_to_excel_col(25), "Z", "Column 25 should map to 'Z'.")

    def test_double_letter_AA_to_AZ(self):
        """
        Tests that the next set of column indices (26 through 51) map to AA-AZ.
        """
        self.assertEqual(colnum_to_excel_col(26), "AA", "Column 26 should map to 'AA'.")
        self.assertEqual(colnum_to_excel_col(27), "AB", "Column 27 should map to 'AB'.")
        self.assertEqual(colnum_to_excel_col(51), "AZ", "Column 51 should map to 'AZ'.")

    def test_double_letter_BA_to_BZ(self):
        """
        Tests that column indices (52 through 77) map to BA-BZ.
        """
        self.assertEqual(colnum_to_excel_col(52), "BA", "Column 52 should map to 'BA'.")
        self.assertEqual(colnum_to_excel_col(77), "BZ", "Column 77 should map to 'BZ'.")

    def test_triple_letter_start(self):
        """
        Tests that column index 702 maps to AAA, which is the first triple-letter column.
        """
        self.assertEqual(colnum_to_excel_col(701), "ZZ", "Column 701 should map to 'ZZ'.")
        self.assertEqual(colnum_to_excel_col(702), "AAA", "Column 702 should map to 'AAA'.")

    def test_negative_index(self):
        """
        Tests that passing a negative column index returns an empty string.
        If your implementation raises an exception, update this test to expect that exception.
        """
        self.assertEqual(colnum_to_excel_col(-1), "", "Negative index should map to ''.")
        self.assertEqual(colnum_to_excel_col(-10), "", "Negative index should map to ''.")


class TestLogStartTime(unittest.TestCase):
    """
    Tests for the log_start_time function, which logs and persists
    the start time of script execution.
    """

    @patch("os.path.exists", return_value=False)
    @patch("builtins.open", new_callable=mock_open)
    @patch("generate_report_excels.logger.info")
    def test_no_existing_file_no_args(self, mock_logger_info, mock_file, mock_exists):
        """
        If the file does NOT exist and args created_before or created_after
        are not supplied, log_start_time should create the file
        and return (None, current_start_time).
        """
        mock_args = MagicMock(created_before=None, created_after=None)
        prev_time, current_time = log_start_time("fake_path.log", mock_args)
        self.assertIsNone(prev_time, "Should return None for prev_time when no file exists.")
        self.assertIsNotNone(current_time, "Should set a current start time.")
        mock_logger_info.assert_any_call("Writing the current start time to the file.")
        mock_file.assert_called_once_with("fake_path.log", 'w')

    @patch("os.path.exists", return_value=False)
    @patch("generate_report_excels.logger.info")
    def test_no_existing_file_with_args(self, mock_logger_info, mock_exists):
        """
        If the file does NOT exist but args created_before or created_after are provided,
        the function should skip writing to the file and return (None, current_start_time).
        """
        mock_args = MagicMock(created_before="2024-01-01T08:30:00Z", created_after=None)
        prev_time, current_time = log_start_time("fake_path.log", mock_args)
        self.assertIsNone(prev_time, "Should return None when file doesn't exist.")
        self.assertIsNotNone(current_time, "Should still return a current start time.")
        # Because args.created_before is supplied, the function
        # should not try to write to the file.

    @patch("os.path.exists", return_value=True)
    @patch("builtins.open", new_callable=mock_open, read_data="2023-01-01T10:00:00Z")
    @patch("generate_report_excels.logger.info")
    def test_existing_file_valid_format(self, mock_logger_info, mock_file, mock_exists):
        """
        If the file exists with a valid datetime string,
        the function should parse it correctly and return (previous_start_time, current_start_time).
        """
        mock_args = MagicMock(created_before=None, created_after=None)
        prev_time, current_time = log_start_time("fake_path.log", mock_args)
        self.assertIsInstance(prev_time, dt.datetime, "prev_time should be a datetime object.")
        self.assertIsNotNone(current_time, "current_time should not be None.")
        mock_file.assert_any_call("fake_path.log", 'r')  # Read existing
        mock_file.assert_any_call("fake_path.log", 'w')  # Write new

    @patch("os.path.exists", return_value=True)
    @patch("builtins.open", new_callable=mock_open, read_data="INVALID_DATETIME")
    @patch("generate_report_excels.logger.warning")
    def test_existing_file_invalid_format(self, mock_logger_warning, mock_file, mock_exists):
        """
        If the file exists but contains an invalid datetime format,
        the function should return (None, current_start_time)
        and log a warning about the invalid format.
        """
        mock_args = MagicMock(created_before=None, created_after=None)
        prev_time, current_time = log_start_time("fake_path.log", mock_args)
        self.assertIsNone(prev_time, "Should return None if file content is invalid.")
        self.assertIsNotNone(current_time, "Should return a new current time.")
        mock_logger_warning.assert_called_once()

    @patch("os.path.exists", return_value=True)
    @patch("builtins.open", new_callable=mock_open, read_data="2023-10-01T09:00:00Z")
    @patch("generate_report_excels.logger.info")
    @patch("generate_report_excels.dt.datetime")
    def test_current_start_time_format(self, mock_datetime, mock_logger_info, mock_file, mock_exists):
        """
        Ensures the current start time is written in '%Y-%m-%dT%H:%M:%SZ' format.
        """
        # Mock datetime.now().strftime(...) to return a dummy time
        mock_datetime.now.return_value.strftime.return_value = "2023-10-01T09:37:00Z"
        mock_args = MagicMock(created_before=None, created_after=None)

        prev_time, current_time = log_start_time("fake_path.log", mock_args)
        self.assertEqual(current_time, "2023-10-01T09:37:00Z",
                         "Current time should follow the expected format.")
        # The function should have opened the file in 'w' mode and saved the new time:
        mock_file().write.assert_called_with("2023-10-01T09:37:00Z")


class TestGetReport(unittest.TestCase):
    """
    Tests for the get_report function, which fetches a JSON report for a given case ID
    from an ICI API endpoint.
    """

    @patch('requests.Session')
    def test_get_report_success(self, mock_session_cls):
        """
        Test that a successful request returns the expected JSON object.
        """
        mock_session = MagicMock()
        mock_response = MagicMock()
        mock_response.json.return_value = {"status": "completed"}
        mock_response.raise_for_status.return_value = None
        mock_session.get.return_value = mock_response
        mock_session_cls.return_value = mock_session

        report = get_report("https://api.ici.example.com/", {"Authorization":"Bearer test"}, "12345")
        self.assertIsNotNone(report, "Expected a valid JSON response.")
        self.assertEqual(report["status"], "completed", "Expected 'completed' status in the returned JSON.")

    @patch('requests.Session')
    def test_get_report_http_error(self, mock_session_cls):
        """
        Test that an HTTP error (e.g. 404, 500) leads to returning None and logs an error.
        """
        mock_session = MagicMock()
        mock_response = MagicMock()
        mock_response.raise_for_status.side_effect = HTTPError("404 Not Found")
        mock_session.get.return_value = mock_response
        mock_session_cls.return_value = mock_session

        report = get_report("https://api.ici.example.com/", {"Authorization":"Bearer test"}, "99999")
        self.assertIsNone(report, "HTTPError should result in None.")

    @patch('requests.Session')
    def test_get_report_request_exception(self, mock_session_cls):
        """
        Test that a generic RequestException also leads to returning None.
        This covers timeouts, connection errors, etc.
        """
        mock_session = MagicMock()
        mock_session.get.side_effect = RequestException("Some network issue")
        mock_session_cls.return_value = mock_session

        report = get_report("https://api.ici.example.com/", {"Authorization":"Bearer test"}, "12345")
        self.assertIsNone(report, "Any RequestException should cause the function to return None.")

    @patch('requests.Session')
    def test_get_report_connection_error(self, mock_session_cls):
        """
        Specifically test a ConnectionError scenario to ensure None is returned.
        """
        mock_session = MagicMock()
        mock_session.get.side_effect = ConnectionError("Unable to connect")
        mock_session_cls.return_value = mock_session

        report = get_report("https://api.ici.example.com/", {"Authorization":"Bearer test"}, "12345")
        self.assertIsNone(report, "ConnectionError should lead to None.")

    @patch('requests.Session')
    def test_get_report_timeout(self, mock_session_cls):
        """
        Specifically test a Timeout scenario to ensure None is returned.
        """
        mock_session = MagicMock()
        mock_session.get.side_effect = Timeout("Timed out")
        mock_session_cls.return_value = mock_session

        report = get_report("https://api.ici.example.com/", {"Authorization":"Bearer test"}, "12345")
        self.assertIsNone(report, "Timeout should lead to None.")


    @patch('requests.Session')
    def test_get_report_with_real_mock_data(self, mock_session_cls):
        """
        Test using the real JSON from test_demo_breast.json. We expect get_report
        to return the same structure when the request is successful.
        """
        # Load the mock JSON data from file
        with open('tests/test_data/test_demo_breast.json', 'r') as f:
            mock_data = json.load(f)

        mock_session = MagicMock()
        mock_response = MagicMock()
        # Simulate a successful response with the real JSON data
        mock_response.json.return_value = mock_data
        mock_response.raise_for_status.return_value = None
        mock_session.get.return_value = mock_response
        mock_session_cls.return_value = mock_session

        report = get_report("https://api.ici.example.com/", {"Authorization":"Bearer token"}, "TEST_DEMO_BREAST")
        self.assertIsNotNone(report, "Expected the function to return the JSON data.")
        self.assertEqual(report, mock_data, "Returned JSON should match the contents of 'test_demo_breast.json'.")

class TestWriteSection(unittest.TestCase):
    def setUp(self):
        # Mock the ExcelWriter
        self.mock_writer = MagicMock()
        self.mock_workbook = MagicMock()
        self.mock_worksheet = MagicMock()

        # Mock references that write_section expects
        self.mock_writer.book = self.mock_workbook
        self.mock_writer.sheets = {"Reported_Variants_and_Metrics": self.mock_worksheet}

        # Mock formatting functions
        format_mock = MagicMock()
        self.mock_workbook.add_format.return_value = format_mock

    def test_write_section_empty_df(self):
        """Test behavior when the DataFrame is empty."""
        empty_df = pd.DataFrame()
        start_pos = write_section(self.mock_writer, empty_df, "Empty Data")
        # Should skip writing headers, go directly to "No variants reported"
        self.assertGreater(start_pos, 0, "Should advance row position even if DF is empty.")
        # Check calls to merge_range with 'No variants reported'
        self.mock_worksheet.merge_range.assert_any_call(
            1, 0, 1, 7, "No variants reported", self.mock_workbook.add_format()
        )

    def test_write_section_basic_df(self):
        """Test behavior when the DataFrame has basic columns and data."""
        df = pd.DataFrame({
            "ColumnA": [1, 2],
            "ColumnB": [3, 4]
        })
        start_pos = write_section(self.mock_writer, df, "Basic Data")
        # Should write the header row plus data rows
        self.assertEqual(start_pos, 1 + 1 + len(df) + 2, "Row position should match DF rows + 2 spacing.")

        # Check header writing
        self.mock_worksheet.write.assert_any_call(1, 0, "ColumnA", self.mock_workbook.add_format())
        self.mock_worksheet.write.assert_any_call(1, 1, "ColumnB", self.mock_workbook.add_format())


if __name__ == '__main__':
    unittest.main()
