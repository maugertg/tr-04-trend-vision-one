import requests
import urllib.parse
from functools import partial
from datetime import datetime, timezone, timedelta

from flask import Blueprint

from api.schemas import ObservableSchema
from api.utils import get_json, get_jwt, jsonify_data

enrich_api = Blueprint("enrich", __name__)

get_observables = partial(get_json, schema=ObservableSchema(many=True))


def format_docs(docs):
    """Format CTIM Response"""
    return {"count": len(docs), "docs": docs}


def group_observables(relay_input):
    # Leave only unique pairs.

    result = []
    for obj in relay_input:
        obj["type"] = obj["type"].lower()

        # Get only supported types.
        if obj["type"] in (
            "domain",
            "email",
            "email_subject",
            "file_name",
            "file_path",
            "hostname",
            "ip",
            "ipv6",
            # "mac_address", # Doesn't exist in Detection fields
            "md5",
            "sha1",
            "sha256",
            "url",
            "user",
            # "user_agent", # Doesn't exist in Detection fields
        ):
            if obj in result:
                continue
            result.append(obj)

    return result


def get_detection_data(host, api_token, observable):
    url = f"https://{host}/v3.0/search/detections"

    # Generate UTC timestamp 30 days ago from now
    startDateTime = (datetime.now(timezone.utc) - timedelta(days=30)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )

    params = {"startDateTime": startDateTime, "top": 100}
    headers = {
        "TMV1-Query": observable,
        "Authorization": f"Bearer {api_token}",
    }

    response = requests.get(url, headers=headers, params=params)

    if response.ok:
        return response.json()


def get_vision_one_outputs(host, api_token, observables):
    """Iterate over observables provided from Threat Reasponse and query Vision One"""
    outputs = []
    for obs in observables:
        observable = obs["value"]
        response = get_detection_data(host, api_token, observable)

        if response:
            response["observable"] = obs
            outputs.append(response)

    return outputs


@enrich_api.route("/deliberate/observables", methods=["POST"])
def deliberate_observables():
    _ = get_jwt()
    _ = get_observables()
    return jsonify_data({})


@enrich_api.route("/observe/observables", methods=["POST"])
def observe_observables():
    jwt = get_jwt()
    host = jwt["host"]
    api_token = jwt["token"]
    observables = group_observables(get_observables())
    print(observables)

    if not observables:
        return jsonify_data({})

    vision_one_outputs = get_vision_one_outputs(host, api_token, observables)

    return vision_one_outputs

    return jsonify_data(relay_output)


@enrich_api.route("/refer/observables", methods=["POST"])
def refer_observables():
    """Trend Micro UI Search URL Example:
    https://portal.xdr.trendmicro.com/#/app/search?start=1665417187&end=1665503587&search_query=1cd61a7744db06e750cb4e1cb1236e19
    """
    jwt = get_jwt()
    host = jwt["host"].replace("api", "portal")
    observables = get_observables()

    # Mapping taken from https://docs.trendmicro.com/en-us/enterprise/trend-micro-vision-one/common-apps/search-app/data-mapping-intro/data-mapping-sdl.aspx
    observable_to_general_search_mapping = {
        "md5": 'FileMD5:"{0}"',
        "sha1": 'FileSHA1:"{0}"',
        "sha256": 'FileSHA2:"{0}"',
        "domain": 'DomainName:"{0}"',
        "email": 'EmailSender:"{0}" OR EmailRecipient:"{0}"',
        "email_subject": 'EmailSubject:"{0}"',
        "file_name": 'FileName:"{0}"',
        "file_path": 'FileFullPath:"{0}"',
        "ip": 'IPv4:"{0}"',
        "ipv6": 'IPv6:"{0}"',
        "url": 'URL:"{0}"',
        "hostname": 'EndpointName:"{0}"',
        "user": 'UserAccount:"{0}"',
    }

    relay_output = []

    # Generate end (now - 30 days) and start (now UTC) epoch timestamps
    end = datetime.utcnow().replace(tzinfo=timezone.utc)
    end_timestamp = int(end.timestamp())
    start = end - timedelta(days=30)
    start_timestamp = int(start.timestamp())

    for obs in observables:

        refer_object = {
            "id": "ref-trend-micro-search-{0}-{1}",
            "title": "Open in Vision One Search",
            "description": "Open in Vision One Search",
            "categories": ["Trend Micro", "Vision One", "Search"],
            "url": None,
        }

        if obs["type"] in observable_to_general_search_mapping:
            refer_object["id"] = refer_object["id"].format(
                obs["type"], urllib.parse.quote(obs["value"])
            )
            search_query = observable_to_general_search_mapping[obs["type"]].format(
                obs["value"]
            )
            url_encoded_search_query = urllib.parse.quote(search_query)
            url = f"https://{host}/#/app/search?start={start_timestamp}&end={end_timestamp}&search_query={url_encoded_search_query}"
            refer_object["url"] = url
            relay_output.append(refer_object)

    return jsonify_data(relay_output)
