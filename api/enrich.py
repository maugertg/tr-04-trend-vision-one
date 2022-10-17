import requests
import ipaddress
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


def get_endpoint_data_by_agent_guid(host, api_token, agent_guid):
    """https://automation.trendmicro.com/xdr/api-v3#tag/Search/paths/~1v3.0~1eiqs~1endpoints/get"""
    url = f"https://{host}/v3.0/eiqs/endpoints"

    headers = {
        "TMV1-Query": f"agentGuid eq '{agent_guid}'",
        "Authorization": f"Bearer {api_token}",
    }

    response = requests.get(url, headers=headers)

    if response.ok:
        return response.json()


def build_target_from_endpoint_obj(message, eventTimeDT):
    def get_ip_type(address):
        try:
            ip = ipaddress.ip_address(address)

            if isinstance(ip, ipaddress.IPv4Address):
                return "ip"

            if isinstance(ip, ipaddress.IPv6Address):
                return "ipv6"
        except ValueError:
            print(f"{address} is an invalid IP address")

    message = message.get("items", [])[0]
    macAddress = message.get("macAddress", {}).get("value")
    ips = message.get("ip", {}).get("value")
    endpointName = message.get("endpointName", {}).get("value")

    target = {
        "type": "endpoint",
        "observables": [],
        "observed_time": {"start_time": eventTimeDT, "end_time": eventTimeDT},
        "os": message.get("osName", "MISSING"),
    }

    if endpointName:
        target["observables"].append({"value": endpointName, "type": "hostname"})

    for value in macAddress:
        target["observables"].append({"value": value, "type": "mac_address"})

    for value in ips:
        target["observables"].append({"value": value, "type": get_ip_type(value)})

    return target


def get_detection_data(host, api_token, observable):
    url = f"https://{host}/v3.0/search/detections"

    # Generate UTC timestamp 30 days ago from now
    startDateTime = (datetime.now(timezone.utc) - timedelta(days=30)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )

    params = {"startDateTime": startDateTime, "top": 100}
    headers = {
        "TMV1-Query": f"{observable}",
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


def extract_sightings(output, observable, host, api_token):
    """Parse Trend Micro Vision One detection object and build CTIM Sighting
    Detection Object from: Get detection data API
    URL: https://automation.trendmicro.com/xdr/api-v3#tag/Search/paths/~1v3.0~1search~1detections/get
    """

    def _make_data_table(message):
        data = {"columns": [], "rows": [[]]}

        for key, value in message.items():
            if (
                not (key.startswith(("rt", "rt_utc", "eventTime", "eventTimeDT")))
                and value
            ):
                data["columns"].append({"name": key, "type": "string"})
                data["rows"][0].append(str(value))

        return data

    eventTime = output.get("eventTime")
    eventTimeDT = output.get("eventTimeDT")
    uuid = output.get("uuid")
    endpointGUID = output.get("endpointGUID")
    endpointHostName = output.get("endpointHostName")

    doc = {
        "confidence": "High",
        "count": 1,
        "description": "Vision One Detection",
        "short_description": f"{output.get('eventName')} - {output.get('eventSubName')}",
        "external_ids": [uuid],
        "id": f"transient:sighting-{uuid}",
        "internal": True,
        "observables": [observable],
        "observed_time": {"start_time": eventTimeDT},
        "data": _make_data_table(output),
        # "relations": [],
        "schema_version": "1.1.12",
        # "sensor": "endpoint",
        # "severity": "string",
        "source": "Vision One Detection",
        "source_uri": f"https://{host.replace('api', 'portal')}/index.html#/app/search?action=new_search&search_type=uuid&search_value={uuid}&search_source=detection&start={eventTime-3600}&end={eventTime+3600}",
        "type": "sighting",
    }

    # doc["relations"].extend(extract_relations(threatInfo, observable))

    if endpointGUID and endpointHostName:
        # endpoint_data = get_endpoint_data_by_agent_guid(host, api_token, endpointGUID)
        # target = build_target_from_endpoint_obj(endpoint_data, eventTimeDT)
        # print(target)

        target = {
            "type": "endpoint",
            "observables": [{"value": endpointHostName, "type": "hostname"}],
            "observed_time": {"start_time": eventTimeDT},
            # "observed_time": {"start_time": eventTimeDT, "end_time": eventTimeDT},
            # "os": message.get("osName", "MISSING"),
        }

        doc.setdefault("targets", []).append(target)

    return doc


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

    if not observables:
        return jsonify_data({})

    vision_one_outputs = get_vision_one_outputs(host, api_token, observables)

    if not vision_one_outputs:
        return jsonify_data({})

    indicators = []
    sightings = []
    relationships = []

    for output in vision_one_outputs:
        items = output.get("items", [])
        observable = output.get("observable")
        for entry in items:
            # output_indicators = entry.get("indicators")
            sightings.append(extract_sightings(entry, observable, host, api_token))
            # if output_indicators:
            #     indicators.extend(extract_indicators(output_indicators))
            #     relationships.extend(extract_relationships(entry))

    # return vision_one_outputs

    relay_output = {}

    if sightings:
        relay_output["sightings"] = format_docs(sightings)
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
