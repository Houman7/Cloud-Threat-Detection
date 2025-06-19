# Cloud-Threat-Detection
This project sets up a lightweight SIEM-like system in AWS using cloudwatch,cloudtrail,lambda and SNS.It detects suspicious activity and and sends real-time alerts via email.

## Features
- Monitoring AWS account activity
- Detecting suspicious or unauthorized behavior 
- Alerting security teams in real-time
  
## Detection Capabilites
- Root account usage	
- MFA not used	
- StopLogging call	
- IAM policy tampering	
- Lambda enumeration	
- Suspicious IP addresses	
- S3 bucket access
## How it Works
- CloudTrail records AWS API activity
- Events are delivered to CloudWatch Logs
- CloudWatch triggers Lambda via subscription filter on matching patterns
- Lambda processes event and publishes to SNS
- SNS sends alerts to your chosen subscribers
