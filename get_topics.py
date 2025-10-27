import argparse
import requests
from requests.auth import HTTPBasicAuth, HTTPDigestAuth
import xml.etree.ElementTree as ET

def is_not_topic(name):
    if "Value" in name:
        return True
    if "MessageInstance" in name:
        return True
    if "DataInstance" in name:
        return True
    if "SourceInstance" in name:
        return True

    return False

def parse_from_parent(paths, node, current_path):
    name = node.tag
    if is_not_topic(name):
        paths.add(current_path)
        return

    if current_path:
        current_path += "/"
        current_path += name
    else:
        current_path = name

    if not len(node):
        paths.add(current_path)

    for child in node:
        parse_from_parent(paths, child, current_path)


def parse_topicset(xml_text):
    namespaces = {
        "wstop": "http://docs.oasis-open.org/wsn/t-1",
        "tt": "http://www.onvif.org/ver10/schema",
        "tnsaxis": "http://www.axis.com/2009/event/topics",
        "tns1": "http://www.onvif.org/ver10/topics",
    }

    root = ET.fromstring(xml_text)
    topicset = root.find(".//wstop:TopicSet", namespaces)
    if topicset is None:
        print("Could not find TopicSet")
        return []

    paths = set()

    for parent in topicset:
        parse_from_parent(paths, parent, "")

    prefixed_paths = []
    for p in paths:
        p = p.replace("{http://www.onvif.org/ver10/topics}", "onvif:")
        p = p.replace("{http://www.axis.com/2009/event/topics}", "axis:")

        prefixed_paths.append(p)

    return sorted(prefixed_paths)


def get_event_instances(
    url: str,
    username: str = None,
    password: str = None,
    proxy: dict = None,
    verify_cert: bool = True,
):

    xml_data = """<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"> <s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema"> <GetEventInstances xmlns="http://www.axis.com/vapix/ws/event1"/> </s:Body> </s:Envelope>"""
    headers = {"Content-Type": "application/xml"}

    if url.startswith("http://"):
        auth = HTTPDigestAuth(username, password) if username and password else None
    else:
        auth = HTTPBasicAuth(username, password) if username and password else None

    response = requests.post(
        url,
        data=xml_data.encode("utf-8"),
        headers=headers,
        auth=auth,
        proxies=proxy,
        verify=verify_cert,
        timeout=30,
    )

    response.raise_for_status()
    return response.text


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Get VAPIX event declarations as a list of topic filters",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
    Examples:
        python3 get_topics.py https://192.168.1.100/vapix/services -u root -p password
        python3 get_topics.py https://camera.example.com/vapix/services --username admin --password secret
        """
    )

    parser.add_argument(
        "-H", "--host",
        help="URL / IP to target device (e.g., https://192.168.1.100"
    )

    parser.add_argument(
        "-u", "--username",
        help="Username"
    )

    parser.add_argument(
        "-p", "--password",
        help="Password"
    )

    parser.add_argument(
        "--proxy",
        help="HTTP(S) proxy URL (e.g., http://proxy.example.com:8080)"
    )

    args = parser.parse_args()

    url = args.host + "/vapix/services"


    if args.proxy:
        proxy_settings = {
            "http": args.proxy,
            "https": args.proxy,
        }
    else:
        proxy_settings = {}

    try:
        result = get_event_instances(
            url,
            username=args.username,
            password=args.password,
            proxy=proxy_settings,
            verify_cert=False,
        )
        topics = parse_topicset(result)
        if len(topics) > 0:
            for t in topics:
                print(t)
            print(f"num topic filters: {len(topics)}")
        else:
            print("Could not find any topics")
    except requests.RequestException as e:
        print("Error:", e)
