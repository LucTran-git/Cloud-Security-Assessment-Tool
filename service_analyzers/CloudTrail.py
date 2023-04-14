import boto3

def enable_data_events_for_cloudtrail(aws_access_key_id, aws_secret_access_key, trail_name):
    # Create a boto3 CloudTrail client
    cloudtrail_client = boto3.client(
        "cloudtrail",
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
    )
    
    # Get the trail's ARN
    trail = cloudtrail_client.describe_trails(trailNameList=[trail_name])['trailList'][0]
    trail_arn = trail['TrailARN']
    
    # Create a boto3 CloudWatch client
    cloudwatch_client = boto3.client(
        "cloudwatch",
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
        aws_session_token=aws_session_token
    )
    
    # Create the event selectors for data events
    event_selector = {
        "ReadWriteType": "All",
        "IncludeManagementEvents": True,
        "DataResources": [
            {
                "Type": "AWS::S3::Object",
                "Values": [
                    "arn:aws:s3:::"
                ]
            },
            {
                "Type": "AWS::Lambda::Function",
                "Values": [
                    "arn:aws:lambda"
                ]
            }
        ]
    }
    
    # Update the trail with the new event selector
    response = cloudtrail_client.put_event_selectors(
        TrailName=trail_arn,
        EventSelectors=[event_selector]
    )
    
    print(f"Data events enabled for CloudTrail trail '{trail_name}'.")
