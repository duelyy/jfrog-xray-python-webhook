import json
import requests
from slack_sdk.webhook import WebhookClient

def violation_sev_section(sev, num_list, sev_count):
    msg_block = f'''{{
            "type": "section",
            "fields": [
                {{
                    "type": "mrkdwn",
                    "text": "{sev} ({num_list} of {sev_count} shown)"
                }}
            ]
        }}'''
    msg_block_load = json.loads(msg_block)
    return msg_block_load
    
def violation_docker_section(event):
    for docker in event['issues']:
        for docker_path in docker['impacted_artifacts']:
            docker_path_name = docker_path['display_name']


    msg_block = f'''{{
            "type": "section",
            "fields": [
                {{
                    "type": "mrkdwn",
                    "text": "Docker: {docker_path_name}"
                }}
            ]
        }}'''
    msg_block_load = json.loads(msg_block)
    return msg_block_load
