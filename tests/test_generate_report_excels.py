import unittest
from pytest import raises, mark, fixture
import requests
import sys
import os
import argparse
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from generate_report_excels import parse_args, setup_api, get_audit_logs, get_report
from unittest.mock import patch


"""
Test the generate_report_excels.py file
"""
@fixture
def mock_args():
    with patch('argparse.ArgumentParser.parse_args') as mock_parse_args:
        mock_parse_args.return_value = argparse.Namespace(
            created_before="2024-01-01T08:30:00Z",
            created_after="2023-01-01T08:30:00Z",
            override_report_pattern="test_pattern"
        )
        yield mock_parse_args

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
        with raises(SystemExit):
            args = parse_args()

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
        with raises(SystemExit):
            args = parse_args()

    @mark.parametrize("created_before, created_after", [
        ("2024-01-01T08:31:00Z", "2024-01-01T08:30:00Z"),
        ("1900-02-01T08:30:00Z", "1899-02-01T08:30:00Z"),
        ("0002-01-01T08:30:00Z", "0001-01-01T08:30:00Z"),
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
            with raises(SystemExit):
                args = parse_args()

    def test_created_before_and_created_after_cannot_be_equal(self, mock_args):
        with patch('argparse.ArgumentParser.parse_args') as mock_parse_args:
            mock_parse_args.return_value = argparse.Namespace(
                created_before="2024-01-01T08:30:00Z",
                created_after="2024-01-01T08:30:00Z",
            )
            with raises(SystemExit):
                args = parse_args()


if __name__ == '__main__':
    unittest.main()

# class TestAPICalls(unittest.TestCase):
#     """
#     Mocked testings for the API calls
#     """

#     @patch('requests.get')
#     def test_get_api_call(self, mock_get):
#         mock_response = unittest.mock.Mock()
#         mock_response.status_code = 200
#         mock_response.json.return_value = {"key": "value"}
#         mock_get.return_value = mock_response
#         response = requests.get('http://example.com/api')
#         self.assertEqual(response.status_code, 200)
#         self.assertEqual(response.json(), {"key": "value"})

#     @patch('requests.post')
#     def test_post_api_call(self, mock_post):
#         mock_response = unittest.mock.Mock()
#         mock_response.status_code = 201
#         mock_response.json.return_value = {"id": 123}
#         mock_post.return_value = mock_response
#         response = requests.post('http://example.com/api', json={"data": "value"})
#         self.assertEqual(response.status_code, 201)
#         self.assertEqual(response.json(), {"id": 123})


# class TestGenerateReportExcels(unittest.TestCase):
#     """
#     Tests for the generate_report_excels functions
#     """

#     @patch('generate_report_excels.requests.get')
#     def test_get_audit_logs(self, mock_get):
#         mock_response = unittest.mock.Mock()
#         mock_response.status_code = 200
#         mock_response.json.return_value = {"content": [{"caseId": "12345"}]}
#         mock_get.return_value = mock_response
#         headers = {"Authorization": "ApiKey test_key"}
#         logs = get_audit_logs("http://example.com", headers, "case.status.updated", "als/api/v1/auditlogs/search")
#         self.assertEqual(logs, [{"caseId": "12345"}])

#     @patch('generate_report_excels.requests.get')
#     def test_get_report(self, mock_get):
#         mock_response = unittest.mock.Mock()
#         mock_response.status_code = 200
#         mock_response.json.return_value = {"status": "completed"}
#         mock_get.return_value = mock_response
#         headers = {"Authorization": "ApiKey test_key"}
#         report = get_report("http://example.com", headers, "12345")
#         self.assertEqual(report, {"status": "completed"})

if __name__ == '__main__':
    unittest.main()