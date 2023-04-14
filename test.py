import boto3
import json
import botocore

from service_analyzers import iam
from service_analyzers import ec2
from service_analyzers import s3
from service_analyzers import vpc

# open session with the account
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

print('Populating service clients...')

print('Acquiring iam client...')
clients = {}
clients['iam'] = session.client('iam')

###---------------------------------------------------EC2 SECTION----------------------------------------------------------------------
#1.since an account can have multiple instances in different regions, get a list of regions where the service is available
print('Acquiring ec2 available regions...')
ec2_regions = []
for regionName in session.get_available_regions('ec2'):
    try:
        print('Getting region...')
        ec2_clientTMP = session.client('ec2', region_name=regionName)
        ec2_clientTMP.describe_instances()
        ec2_regions.append(regionName)
    except botocore.exceptions.ClientError as e:
        print(f"region unavailable: {regionName}: {str(e)}")
        pass

#2.create a list of service "client" objects for each region for the service and obtain a description of those EC2 instances
print('Creating list of ec2 clients...')
ec2_clients_List = []


for i in range(len(ec2_regions)):
    ec2_clients_List.append(session.client('ec2', ec2_regions[i]))

clients['ec2'] = ec2_clients_List

iam.check_IAM_EC2_configurations(clients['ec2'])
# ---------------------------------------------------------------------------------------------------------------------------------------

# clients['s3'] = session.client('s3')
# clients['vpc'] = session.client('vpc')

#iam.run_all_checks(clients['iam'])
iam.analyze_local_managed_policies(clients['iam'])  
#print(clients['iam'])