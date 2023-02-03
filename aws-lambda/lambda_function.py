import json
import requests
import re
import urllib
from urllib.parse import urlparse

from slack_sdk.webhook import WebhookClient
from violation_function import *

SLACK_URL = "https://hooks.slack.com/services/secret-slack-webhook-id"

def lambda_handler(event, context):

    msg = slack_template(event)
    send_slack_message(msg)

    return {
        'statusCode': 200,
        'body': msg
    }

def slack_template(event):
    
    critical_count = count_severity(event, "Critical")
    high_count = count_severity(event, "High")
    medium_count = count_severity(event, "Medium")
    low_count = count_severity(event, "Low")
    sev_list = ["Critical", "High", "Medium", "Low"]

    payload_block = []
    
    header_block = f'''{{
            "type": "header",
            "text": {{
                "type": "plain_text",
                "text": "Security Violation ({critical_count} Critical, {high_count} High, {medium_count} Medium, {low_count} Low)"
            }}
        }}'''
    header_block_load = json.loads(header_block)
    
    # Header that shows summary of high, medium, low count
    payload_block.append(header_block_load)
    # Output watch and policy name
    payload_block.append(watch_policy_section(event))
    
    #TODO: Tidy the below up using map functions
    
    # Critical
    if critical_count > 0:
        payload_block.append(violation_sev_section("Critical", critical_count))
        payload_block.append(violation_docker_section("Critical", event))
        payload_block.append(violation_cve("Critical", event))
        payload_block.append(build_artifactory_url(event))
    
    # High
    if high_count > 0:
        payload_block.append(violation_sev_section("High", high_count))
        payload_block.append(violation_docker_section("High", event))
        payload_block.append(violation_cve("High", event))
        payload_block.append(build_artifactory_url(event))
    
    # Medium
    if medium_count > 0:
        payload_block.append(violation_sev_section("Medium", medium_count))
        payload_block.append(violation_docker_section("Medium", event))
        payload_block.append(violation_cve("Medium", event))
        payload_block.append(build_artifactory_url(event))
    
    # Low
    if low_count > 0:
        payload_block.append(violation_sev_section("Low", low_count))
        payload_block.append(violation_docker_section("Low", event))
        payload_block.append(violation_cve("Low", event))
        payload_block.append(build_artifactory_url(event))

    return payload_block

def count_severity(event, sev):
    count = 0
    for severity in event['issues']:
        if severity['severity'] == sev and severity['type'] == "security":
            count += 1

    return count

def send_slack_message(payload):
    webhook = WebhookClient(SLACK_URL)

    response = webhook.send(
        text="fallback",
        blocks = payload
    )

