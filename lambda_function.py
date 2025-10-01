import json
import boto3
import gzip
import base64
import os
import logging

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize clients
sns = boto3.client('sns')

# Get SNS Topic ARN from environment variable
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN', 'arn:aws:sns:us-east-1:938108731028:MySecurityAlerts')

# Configuration
CRITICAL_IAM_EVENTS = [
    'CreatePolicy', 'DeletePolicy', 'PutUserPolicy', 'PutRolePolicy',
    'PutGroupPolicy', 'AttachUserPolicy', 'DetachUserPolicy',
    'CreateAccessKey', 'UpdateAccessKey', 'DeleteAccessKey',
    'CreateUser', 'DeleteUser', 'CreateLoginProfile'
]

CLOUDTRAIL_TAMPERING_EVENTS = [
    'StopLogging', 'DeleteTrail', 'UpdateTrail'
]

LAMBDA_ENUMERATION_EVENTS = [
    'ListFunctions', 'GetFunction', 'ListAliases', 'ListVersionsByFunction'
]

def lambda_handler(event, context):
    """
    Enhanced CloudTrail monitoring with multiple security detection capabilities
    """
    alerts = []
    
    try:
        if 'awslogs' in event:
            # Decode and decompress CloudWatch Logs data
            compressed_payload = base64.b64decode(event['awslogs']['data'])
            decompressed_payload = gzip.decompress(compressed_payload)
            payload = json.loads(decompressed_payload)
            
            logger.info(f"Processing log group: {payload.get('logGroup', 'Unknown')}")
            logger.info(f"Number of log events: {len(payload.get('logEvents', []))}")
            
            for log_event in payload.get('logEvents', []):
                try:
                    message = json.loads(log_event.get('message', '{}'))
                    
                    # Run all security checks
                    security_alerts = check_security_events(message)
                    alerts.extend(security_alerts)
                        
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse log event message: {e}")
                    continue
                    
        else:
            logger.info("No 'awslogs' key found in event - may not be a CloudWatch Logs trigger")
            
    except Exception as e:
        logger.error(f"Error processing event: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps(f'Error processing events: {str(e)}')
        }
    
    # Send alert if any security events detected
    if alerts:
        send_alert(alerts)
        logger.info(f"Sent SNS alert for {len(alerts)} security events")
    
    return {
        'statusCode': 200,
        'body': json.dumps(f'Processed {len(alerts)} security alerts')
    }

def check_security_events(message):
    """
    Check for various security-related events
    """
    alerts = []
    
    user_identity = message.get('userIdentity', {})
    event_name = message.get('eventName', '')
    event_source = message.get('eventSource', '')
    source_ip = message.get('sourceIPAddress', '')
    
    # Root account usage
    if is_root_user_activity(user_identity):
        alerts.append(f"ROOT USER ACTIVITY: {event_name} from IP {source_ip}")
    
    # MFA not used
    mfa_alert = check_mfa_usage(message, user_identity)
    if mfa_alert:
        alerts.append(mfa_alert)
    
    # StopLogging call & CloudTrail tampering
    if event_name in CLOUDTRAIL_TAMPERING_EVENTS:
        alerts.append(f"CLOUDTRAIL TAMPERING: {event_name} by {user_identity.get('arn', 'Unknown')}")
    
    # IAM policy tampering
    if event_name in CRITICAL_IAM_EVENTS:
        alerts.append(f"IAM POLICY TAMPERING: {event_name} by {user_identity.get('arn', 'Unknown')}")
    
    # Lambda enumeration
    if event_source == 'lambda.amazonaws.com' and event_name in LAMBDA_ENUMERATION_EVENTS:
        alerts.append(f"LAMBDA ENUMERATION: {event_name} from IP {source_ip}")
    
    # bucket access
    if event_source == 's3.amazonaws.com':
        bucket_name = message.get('requestParameters', {}).get('bucketName', 'Unknown')
        alerts.append(f"S3 BUCKET ACCESS: {event_name} on bucket {bucket_name} from IP {source_ip}")
    
    return alerts

def is_root_user_activity(user_identity):
    """
    Check if the activity was performed by the root user
    """
    user_type = user_identity.get('type', '')
    user_name = user_identity.get('userName', '')
    account_id = user_identity.get('accountId', '')
    
    # Root user can be identified by type 'Root' or specific userName patterns
    return (user_type == 'Root' or 
            user_name == 'root' or
            (user_type == 'IAMUser' and user_name.endswith('<root>')))

def check_mfa_usage(message, user_identity):
    """
    Check if MFA was not used for sensitive operations
    """
    additional_data = message.get('additionalEventData', {})
    event_name = message.get('eventName', '')
    
    # Sensitive operations that should require MFA
    sensitive_operations = [
        'CreateAccessKey', 'DeleteAccessKey', 'UpdateAccessKey',
        'ChangePassword', 'CreateLoginProfile', 'UpdateLoginProfile'
    ]
    
    if (event_name in sensitive_operations and 
        'MFA' not in str(additional_data) and
        user_identity.get('type') != 'Root'):  # Root doesn't use MFA in the same way
        
        return f"MFA NOT USED: {event_name} by {user_identity.get('userName', 'Unknown')} without MFA"
    
    return None

def send_alert(alerts):
    """
    Send alert via SNS
    """
    try:
        # Format the alert message
        message_body = "AWS SECURITY ALERTS\n\n"
        message_body += "The following security events were detected:\n\n"
        message_body += "\n".join([f"• {alert}" for alert in alerts])
        message_body += f"\n\nTotal events detected: {len(alerts)}"
        
        # Add timestamp and recommendation
        from datetime import datetime
        message_body += f"\n\nTimestamp: {datetime.utcnow().isoformat()}Z"
        message_body += "\n\nRecommended actions:"
        message_body += "\n- Review CloudTrail logs for these events"
        message_body += "\n- Verify if these actions are authorized"
        message_body += "\n- Check IAM policies and permissions"
        message_body += "\n- Consider enabling MFA for all users"
        
        
        if len(message_body) > 256000:
            message_body = message_body[:256000] + "\n\n... (message truncated)"
        
        response = sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=f"AWS Security Alert: {len(alerts)} Security Events Detected",
            Message=message_body
        )
        logger.info(f"SNS message published with ID: {response['MessageId']}")
        
    except Exception as e:
        logger.error(f"Failed to send SNS alert: {str(e)}")
        raise



