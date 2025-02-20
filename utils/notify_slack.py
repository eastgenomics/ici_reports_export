import os
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import json
from dotenv import load_dotenv

class SlackClient:
    def __init__(self):
        required_vars = {
         "SLACK_TOKEN": "slack_token",
         "SLACK_LOG_CHANNEL": "slack_log_channel",
         "SLACK_ALERT_CHANNEL": "slack_alert_channel"
        }
        missing_vars = [
            env_var for env_var, attr in required_vars.items()
            if not os.getenv(env_var)
        ]
        if missing_vars:
            raise ValueError(f"Missing required environment variables: {', '.join(missing_vars)}")
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
        try:
            response = requests.post(webhook_url,
                                     json=payload,
                                     timeout=30)
            response.raise_for_status()
        except requests.exceptions.Timeout:
            raise Exception("Request timed out")
        except requests.exceptions.TooManyRedirects:
            raise Exception("Too many redirects")
        except requests.exceptions.ConnectionError:
            raise Exception("Connection error occurred")
        except requests.exceptions.HTTPError as e:
            raise Exception(f"HTTP error occurred: {e.response.status_code} - {e.response.text}")
        except requests.exceptions.RequestException as e:
            raise Exception(f"Request failed: {e}")

        if response.status_code != 200:
            raise Exception(f"Request failed with status {response.status_code}, {response.text}")
        else:
            print(f"Message posted to {channel} channel")
