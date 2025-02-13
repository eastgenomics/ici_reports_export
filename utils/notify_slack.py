import os
import sys
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import json
from dotenv import load_dotenv

class SlackClient:
    def __init__(self):
        load_dotenv()  # Load environment variables
        self.webhooks = {
            "log": os.getenv("SLACK_LOG_WEBHOOK"),
            "alerts": os.getenv("SLACK_ALERTS_WEBHOOK")
        }

        # Ensure webhooks exist
        if not self.webhooks["log"] or not self.webhooks["alerts"]:
            raise ValueError("One or both Slack webhook URLs are missing in the environment")


    def post_message(self, message, channel) -> None:
        """
        Post message to provided webhook URL, used for posting messages to
        specific Slack channel

        Parameters
        ----------
        message : str
            message to post to Slack
        channel : str
            channel to post message to

        Outputs
        -------
        Sends POST request to Slack webhook URL.
        """
        webhook_url = self.webhooks.get(channel)

        if not webhook_url:
            raise ValueError(f"Invalid webhook channel: {channel}")

        payload = {"text": message}
        response = requests.post(webhook_url, json=payload, timeout=30)

        if response.status_code != 200:
            raise Exception(f"Request failed with status {response.status_code}, {response.text}")
