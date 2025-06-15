import json
import boto3
import gzip
import base64

sns = boto3.client('sns')

# Replace with your SNS Topic ARN
SNS_TOPIC_ARN = "arn:aws:sns:us-east-1:938108731028:MySecurityAlerts"

def lambda_handler(event, context):
    alerts = []

    if 'awslogs' in event:
        compressed_payload = base64.b64decode(event['awslogs']['data'])
        decompressed_payload = gzip.decompress(compressed_payload)
        payload = json.loads(decompressed_payload)

        print("Decoded CloudTrail log:", json.dumps(payload, indent=2))

        for log_event in payload['logEvents']:
            message = json.loads(log_event['message'])
            user_type = message.get('userIdentity', {}).get('type', '')
            event_name = message.get('eventName', '')

            if user_type == 'Root':
                alerts.append(f" Root user activity detected: {event_name}")
    else:
        print("No 'awslogs' key found in event.")

    if alerts:
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject="🚨 AWS Security Alert",
            Message='\n'.join(alerts)
        )
        print("SNS alert sent.")

    return {
        'statusCode': 200,
        'body': json.dumps('Processed events')
    }

