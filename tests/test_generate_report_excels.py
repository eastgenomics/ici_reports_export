import sys
import os
import json
import datetime as dt

from unittest.mock import patch
import unittest
from pytest import raises, mark, fixture
import re
import argparse

sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..')))
from generate_report_excels import parse_args, \
    log_start_time, setup_api, get_audit_logs, \
    get_report, extract_data_from_report_json

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

        # check if the CNVs return the correct transcript
        for variant in cnvs_variants_info:
            assert re.match(r'^[A-Z][A-Z0-9]*$', variant['Gene'])

    def test_CNVs_return_pathogenicity(self, report_json, return_test_demo_breast):
        sample_id, case_info, snvs_variants_info, \
            cnvs_variants_info, indels_variants_info, \
                tmb_msi_variants_info = return_test_demo_breast
        print(cnvs_variants_info)
        # check if the CNVs return the correct transcript
        for variant in cnvs_variants_info:
            print(variant['Pathogenicity'])
            pathogenicity_list = variant['Pathogenicity'].split(', ')
            print(pathogenicity_list)
            list_accceptable_terms = ['Likely Pathogenic', 'Pathogenic',
                                      'Likely Oncogenic', 'Oncogenic']
            assert all(
                pathogenicity in list_accceptable_terms for pathogenicity in pathogenicity_list
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
            prev_time, current_time = log_start_time(
                "tests/test_data/script_start_time.log")
            assert current_time == time_value

    def test_log_start_time_read_raises_error_when_not_found(self):
        """
        Test that a RuntimeError is raised when
        log_start_time is called with a non-existing path.
        """
        with raises(RuntimeError):
            log_start_time("invalid_path.log")


if __name__ == '__main__':
    unittest.main()
