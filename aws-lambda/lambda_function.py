import json
import requests
from slack_sdk.webhook import WebhookClient
from violation_function import *

NUM_LIST = 5
SLACK_URL = "https://hooks.slack.com/services/secret-slack-webhook-id"

def lambda_handler(event, context):

    msg = slack_template(event)
    send_slack_message(msg)

    return {
        'statusCode': 200,
        'body': msg
    }

def slack_template(event):
    
    high_count = count_severity(event, "High")
    medium_count = count_severity(event, "Medium")
    low_count = count_severity(event, "Low")

    payload_block = []
    
    header_block = f'''{{
            "type": "header",
            "text": {{
                "type": "plain_text",
                "text": "Security Violation ({high_count} High, {medium_count} Medium, {low_count} Low)"
            }}
        }}'''
    header_block_load = json.loads(header_block)
    
    payload_block.append(header_block_load)
    
    # High
    payload_block.append(violation_sev_section("High", NUM_LIST, high_count))
    payload_block.append(violation_docker_section(event))
    
    for issue in event['issues']:
        if issue['severity'] == "High" and issue['type'] == security:
            
    
    # # Medium
    # payload_block.append(violation_sev_section("Medium", NUM_LIST, medium_count))
    # payload_block.append(violation_docker_section(event))
    
    # # Low
    # payload_block.append(violation_sev_section("Low", NUM_LIST, low_count))
    # payload_block.append(violation_docker_section(event))

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

