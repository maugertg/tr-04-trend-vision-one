import requests
import datetime
from flask import Blueprint

from api.utils import get_jwt, jsonify_data, jsonify

health_api = Blueprint("health", __name__)


def str_to_datetime_ojb(date_string):
    fmt = "%Y-%m-%dT%H:%M:%S.%fZ"
    return datetime.datetime.strptime(date_string, fmt).replace(
        tzinfo=datetime.timezone.utc
    )


def list_suspicious_objects(host, api_token):
    """Query Trend Micro Vision One API List suspicious objects API for 1 object
    https://automation.trendmicro.com/xdr/api-v3#tag/Suspicious-Object-List/paths/~1v3.0~1threatintel~1suspiciousObjects/get
    """
    url = f"https://{host}/v3.0/threatintel/suspiciousObjects?top=1"
    headers = {"Authorization": f"Bearer {api_token}"}
    # data = {"data": {"apiToken": f"{api_token}"}}
    response = requests.get(url, headers=headers)

    return response


@health_api.route("/health", methods=["POST"])
def health():
    jwt = get_jwt()
    host = jwt["host"]
    api_token = jwt["token"]

    trend_response = list_suspicious_objects(host, api_token)

    response = {}

    if trend_response.ok:
        response["data"] = {"status": "ok"}
    else:
        response["errors"] = [
            {
                "code": "trend-micro-api-communication-error",
                "message": f"Something went wrong querying the API using token: {api_token[:5]}...{api_token[-5:]}. The API returned status code {trend_response.status_code}",
                "type": "error",
            }
        ]

    return jsonify(response)
