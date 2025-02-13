import sys
import os
import json
from io import StringIO
from contextlib import contextmanager


from unittest.mock import patch, Mock
import unittest
from pytest import raises, mark, fixture
import re
import requests
import argparse

import pytest

sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..')))

from generate_report_excels import parse_args, \
    log_start_time, get_audit_logs, \
    extract_data_from_report_json, \
    setup_logging, send_outcome_notification

from utils.notify_slack import SlackClient

"""
Tests for the generate_report_excels.py file
"""
logger, error_collector = setup_logging()

@fixture
def mock_args():
    with patch('argparse.ArgumentParser.parse_args') as mock_parse_args:
        mock_parse_args.return_value = argparse.Namespace(
            created_before="2024-01-01T08:30:00Z",
            created_after="2023-01-01T08:30:00Z",
            override_report_pattern="test_pattern"
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
            )
            with raises(ValueError):
                _args = parse_args()

    # def test_created_before_and_created_after_cannot_be_equal(self, mock_args):
    #     with patch('argparse.ArgumentParser.parse_args') as mock_parse_args:
    #         mock_parse_args.return_value = argparse.Namespace(
    #             created_before="2024-01-01T08:30:00Z",
    #             created_after="2024-01-01T08:30:00Z",
    #         )
    #         with raises(RuntimeError):
    #             _args = validate_date()


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
            mock_args = argparse.Namespace(created_before=None, created_after=None)
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

    @pytest.mark.parametrize("error_code", [300, 404, 500])
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
    def test_no_errors(self, mock_get_collected_errors, mock_slack_post_message):
        mock_get_collected_errors.return_value = []
        with self.capture_stdout() as stdout:
            send_outcome_notification()
        output = stdout.getvalue()
        mock_slack_post_message.assert_called_once_with(message="Ici-report-export script ran successfully.",
                                                        channel="log")
        self.assertIn("No errors to notify.", output)

    @patch('utils.notify_slack.SlackClient.post_message')
    @patch('generate_report_excels.get_collected_errors')
    def test_runtime_errors(self, mock_get_collected_errors, mock_slack_post_message):
        mock_get_collected_errors.return_value = [
            "2025-02-07 13:53:42,140 - ERROR - Runtime Error: Some reports were not generated."
        ]
        expected_notification = ":gear: **Runtime Errors:**\nRuntime Error: Some reports were not generated."
        send_outcome_notification()
        mock_slack_post_message.assert_called_once_with(message=expected_notification,
                                                        channel="alerts")

    @patch('utils.notify_slack.SlackClient.post_message')
    @patch('generate_report_excels.get_collected_errors')
    def test_case_errors(self, mock_get_collected_errors, mock_slack_post_message):
        mock_get_collected_errors.return_value = [
            "2025-02-07 13:53:42,140 - ERROR - Case ID 12345 not found"
        ]
        expected_notification = ":x: **Case Errors:**\nCase ID 12345 not found"
        send_outcome_notification()
        mock_slack_post_message.assert_called_once_with(message=expected_notification,
                                                        channel="alerts")

    @patch('utils.notify_slack.SlackClient.post_message')
    @patch('generate_report_excels.get_collected_errors')
    def test_variant_errors(self, mock_get_collected_errors, mock_slack_post_message):
        mock_get_collected_errors.return_value = [
            "2025-02-07 13:53:42,140 - ERROR - Unknown variant type: XYZ"
        ]
        expected_notification = ":x: **Variant Errors:**\nUnknown variant type: XYZ"
        send_outcome_notification()
        mock_slack_post_message.assert_called_once_with(message=expected_notification,
                                                        channel="alerts")

    @patch('utils.notify_slack.SlackClient.post_message')
    @patch('generate_report_excels.get_collected_errors')
    def test_other_errors(self, mock_get_collected_errors, mock_slack_post_message):
        mock_get_collected_errors.return_value = [
            "2025-02-07 13:53:42,140 - ERROR - Some other error occurred"
        ]
        expected_notification = ":exclamation: **Other Errors:**\nSome other error occurred"
        send_outcome_notification()
        mock_slack_post_message.assert_called_once_with(message=expected_notification,
                                                        channel="alerts")

    @contextmanager
    def capture_stdout(self):
        old_stdout = sys.stdout
        sys.stdout = StringIO()
        try:
            yield sys.stdout
        finally:
            sys.stdout = old_stdout



if __name__ == '__main__':
    unittest.main()
