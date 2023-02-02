import json
import requests
from slack_sdk.webhook import WebhookClient

# TODO: Figure out how to use another method for multiline msg_block. Formatting is not great.

def violation_sev_section(sev, sev_count):
    msg_block = f'''{{
            "type": "section",
            "fields": [
                {{
                    "type": "mrkdwn",
                    "text": "*{sev}*: ({sev_count})"
                }}
            ]
        }}'''
    msg_block_load = json.loads(msg_block)
    return msg_block_load

def violation_docker_section(sev, event):
    docker_path_list = []
    for docker in event['issues']:
        for docker_impacted_artifacts in docker['impacted_artifacts']:
            if docker['severity'] == sev and docker['type'] == "security" and docker_impacted_artifacts['pkg_type'] == "Docker":
                # docker_path_list.append(docker_impacted_artifacts['display_name'])
                docker_display_name = docker_impacted_artifacts['display_name']

    docker_path_list.append(docker_display_name)

    msg_block = f'''{{
            "type": "section",
            "text": {{
                    "type": "mrkdwn",
                    "text": "*Docker*: {docker_path_list}"
            }}
        }}'''
    msg_block_load = json.loads(msg_block)
    return msg_block_load

def violation_cve(sev, event):
    cve_list = []
    for cve in event['issues']:
        if cve['severity'] == sev and cve['type'] == "security":
            cve_list.append(cve['cve'])

    msg_block = f'''{{
            "type": "section",
            "text": {{
                    "type": "mrkdwn",
                    "text": "*CVE*: {cve_list}"
            }}
        }}'''
    msg_block_load = json.loads(msg_block)
    return msg_block_load

def watch_policy_section(event):
    watch_name = event['watch_name']
    policy_name = event['policy_name']
    msg_block = f'''{{
            "type": "section",
            "fields": [
                {{
                    "type": "mrkdwn",
                    "text": "*Watch Name*: {watch_name}"
                }},
                {{
                    "type": "mrkdwn",
                    "text": "*Policy Name*: {policy_name}"
                }}
            ]
        }}'''
    msg_block_load = json.loads(msg_block)
    return msg_block_load

def empty_section(sev):
    msg_block = f'''{{
            "type": "section",
            "fields": [
                {{
                    "type": "mrkdwn",
                    "text": "*{sev}*: Nothing to see here."
                }}
            ]
        }}'''
    msg_block_load = json.loads(msg_block)
    return msg_block_load
