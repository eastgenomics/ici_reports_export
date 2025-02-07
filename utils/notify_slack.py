import os
import sys
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

class Slack():
    """
    Slack related functions
    """
    def __init__(self) -> None:
        self.slack_token = os.getenv("SLACK_TOKEN")
        self.slack_log_channel = os.getenv("SLACK_LOG_CHANNEL")
        self.slack_alert_channel = os.getenv("SLACK_ALERT_CHANNEL")


    def send(self, message, log=False, alert=False):
        """
        Send notification to Slack

        Parameters
        ----------
        message : str
            message to send to Slack
        log : bool
            if to send message to specified Slack log channel
        alert : bool
            if to send message to specified Slack alert channel
        """
        if not log and not alert:
            # only one should be specified
            raise RuntimeError(
                "ERROR: No Slack channel specified for sending alert"
            )

        if log and alert:
            raise RuntimeError(
                "ERROR: both log and alert specified for Slack channel."
            )

        if log:
            channel = self.slack_log_channel
        else:
            channel = self.slack_alert_channel

            message = (
                f":warning: *Error in ici-report-export*\n\n"
                f"Error: {message}"
            )

        print(
            f"Sending message to Slack channel {channel}\n\n{message}",
            sys.stderr
        )

        http = requests.Session()
        retries = Retry(total=5, backoff_factor=10, allowed_methods=['POST'])
        http.mount("https://", HTTPAdapter(max_retries=retries))

        try:
            response = http.post(
                'https://slack.com/api/chat.postMessage', {
                    'token': self.slack_token,
                    'channel': f"#{channel}",
                    'text': message
                }).json()

            if not response['ok']:
                # error in sending slack notification
                print(
                    f"Error in sending slack notification: {response.get('error')}"
                )
        except Exception as err:
            print(
                f"Error in sending post request for slack notification: {err}"
            )