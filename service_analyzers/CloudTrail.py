import boto3
import json
import botocore.exceptions

cloudtrail_clients_List = []

cloudtrail_report = {}  # dict of (list of dicts)


# { 'policy_name' : [{'warning' : 'text', 'explanation' : 'text', 'recommendation' : 'text'}, ...] }
# We separate the warning info in this way to make it easier to format the report in different ways e.g. txt vs csv

# helper used to print contents of dict as text or json.
def dict_printer(dict, file_format):
    # Write warnings and recommendations to a log file\n
    # Parameters: file format\n
    # Returns: filepath of written file
    if file_format == 'txt':
        filepath = 'logs/cloudtrail_report.txt'

        with open(filepath, "w") as f:
            for warning_category, warnings in dict.items():
                f.write(f"----- Warnning Category: {warning_category} -----\n")
                for warning in warnings:
                    f.write(f"| Warnning | \n")
                    f.write(f" {warning['warning']} \n")
                    f.write(f"| Explanation | \n")
                    f.write(f" {warning['explanation']} \n")
                    f.write(f"| Recommendation | \n")
                    f.write(f" {warning['recommendation']} \n")
                    f.write("\n")

    if file_format == 'json':
        filepath = 'logs/cloudtrail_report.json'

        # Convert the dict to a JSON string with indentation
        json_str = json.dumps(dict, indent=4)

        # Write the JSON string to a file
        with open(filepath, "w") as f:
            f.write(json_str)

    return filepath


# helper used to append an instance of a warning to EC2_VPC_checks[warning_name]
def cloudtrail_checks_writer(warning_category, error_dict):
    if warning_category not in cloudtrail_report:
        cloudtrail_report[warning_category] = []

    cloudtrail_report[warning_category].append(error_dict)


# data events isn't present:
"""

                dict = {"warning": "IAM role not attached to EC2 instance ID: "
                        ,"explanation": "EC2 instances should use an IAM role instead of hard-coded AWS credentials"
                        , "recommendation": "Attach an IAM role to the EC2 instance using the EC2 console or the AWS CLI"}

                cloudtrail_checks_writer("polivy name or catogry here", dict)

"""


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
    


def populate_client_list():
    global cloudtrail_clients_List
    try:
        with open('Credentials.json', 'r') as credsFile:
            credsData = json.load(credsFile)

            if (not credsData['AWS']['access_key_id'] or not credsData['AWS']['secret_access_key']):
                credsData['AWS']['access_key_id'] = input("Please enter Access Key ID:")
                credsData['AWS']['secret_access_key'] = input("Please enter Secret Access Key:")

                with open('Credentials.json', 'w') as credsFileOut:
                    json.dump(credsData, credsFileOut, indent=4)

        accessKeyId = credsData['AWS']['access_key_id']
        secretAccessKey = credsData['AWS']['secret_access_key']

        session = boto3.Session(aws_access_key_id=accessKeyId, aws_secret_access_key=secretAccessKey)

        # 1. since an account can have multiple instances in different regions, get a list of regions where the service is available
        cloudtrail_regions = []

        for regionName in session.get_available_regions('cloudtrail'):
            try:
                cloudtrail_clientTMP = session.client('cloudtrail', region_name=regionName)
                response = cloudtrail_clientTMP.lookup_events(LookupAttributes=[])
                cloudtrail_regions.append(regionName)
            except botocore.exceptions.ClientError as e:
                print(f"region unavailable: {regionName}: {str(e)}")


        # 2. create a list of service "client" objects for each region for the service and obtain a description of those cloudtrail instances
        #cloudtrail_clients_List = []
        for i in range(len(cloudtrail_regions)):
            cloudtrail_clients_List.append(session.client('cloudtrail', cloudtrail_regions[i]))
            try:
                trails = cloudtrail_clients_List[-1].describe_trails()
                print(f"Found {len(trails['trailList'])} trails in {cloudtrail_regions[i]}")
            except botocore.exceptions.ClientError as e:
                print(f"Failed to get trails in {cloudtrail_regions[i]}: {str(e)}")

    except Exception as e:
        print(f"Error occurred: {str(e)}")


#cloudtrail_clients_List = []


def check_data_events_included(cloudtrail_clients_List):
    for cloudtrail_client in cloudtrail_clients_List:
        # List all trails
        trails = cloudtrail_client.describe_trails()
        print(trails)
        # Iterate through trails and check if data events are included
        for trail in trails['trailList']:
            trail_name = trail['Name']
            try:
                # Get the event selectors for the current trail
                #event_selectors = cloudtrail_client.get_event_selectors(TrailName=trail_name)
                event_selectors = trail.get('EventSelectors', [])
                # Check if data events are included in the trail configuration
                data_events_included = any(
                    selector['IncludeManagementEvents'] and selector['DataResources']
                    for selector in event_selectors['EventSelectors']
                )
            except Exception as e:

                warning_dict = {"warning": f"data events are not included within  cloudtrail: '{trail_name}'.",
                "explanation": "data events are a type of event that provides detailed information about operations performed on user data in AWS services",
                "recommendation": f"make sure data events are enabled alongside the Trail: '{trail_name}'."}
                cloudtrail_checks_writer("Data events check", warning_dict)



def check_log_file_validation_enabled(cloudtrail_clients_List):
    for cloudtrail_client in cloudtrail_clients_List:
        # List all trails
        trails = cloudtrail_client.describe_trails()

        # Iterate through trails and check if log file validation is enabled
        for trail in trails['trailList']:
            trail_name = trail['Name']
            trail_arn = trail['TrailARN']  # Get the Trail ARN
            try:
                # Get the current trail's status using the Trail ARN
                trail_status = cloudtrail_client.get_trail_status(Name=trail_arn)

                # Check if log file validation is enabled in the trail configuration
                log_file_validation_enabled = trail_status.get('LogFileValidationEnabled', False)

                if log_file_validation_enabled:
                    print(f'Log file validation is enabled in the trail "{trail_arn}".')
                else:
                    print(f'Log file validation is NOT enabled in the trail "{trail_name}".')
                    warning_dict = {"warning": f"Log file validation is NOT enabled in the trail '{trail_name}'.",
                                    "explanation": "Enabling log file validation ensures the integrity and authenticity of CloudTrail log files.",
                                    "recommendation": f"Enable log file validation for the CloudTrail trail '{trail_name}'."}
                    cloudtrail_checks_writer("Log File Validation Checks", warning_dict)

            except cloudtrail_client.exceptions.TrailNotFoundException:
                print(f'Trail "{trail_name}" not found in region {cloudtrail_client.meta.region_name}.')
            except KeyError as e:
                print(f'Error getting trail status for trail "{trail_name}": {e}')
            except Exception as e:
                print(f'Error getting trail status for trail "{trail_name}": {e}')

def get_all_warnings():
    return cloudtrail_report

def starting_function():
    # Assuming that starting_function() fills cloudtrail_clients_List with CloudTrail clients
    
    populate_client_list()
    
    # Check data events for each CloudTrail client in the list
    check_data_events_included(cloudtrail_clients_List)

    # Check log file validation for each CloudTrail client in the list
    check_log_file_validation_enabled(cloudtrail_clients_List)

    dict_printer(cloudtrail_report, 'txt')

if __name__ == 'main':
    starting_function()